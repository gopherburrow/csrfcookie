// This file is part of Gopher Burrow CSRF Protection Cookie.
//
// Gopher Burrow CSRF Protection Cookie is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Gopher Burrow CSRF Protection Cookie is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Gopher Burrow CSRF Protection Cookie.  If not, see <http://www.gnu.org/licenses/>.

//Package csrfcookie contains an Cross Site Request Forgery (CSRF) protection mechanism utilizing the Double-Submit-Cookie pattern with a JWT token.
//
//It tries to be server-side-stateless as possible using Origin and Referer cross-site-checks and JWT (JSON Web Token) with HMAC-SHA256 signatures.
//
//Warning: The security mechanism utilized by this package is not able to protect from CSRF if there is a XSS (Cross Site Scripting) flaw in the pages served (as most CSRF protection mechanisms).
//
//Double-Submit-Cookie
//
//In a server state changing operation (POST, PUT or DELETE), a previously created cookie value is checked against a form field or custom HTTP header value.
//
//More information to Double-Submit-Cookie can be found at https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Double_Submit_Cookie .
package csrfcookie

import (
	"crypto/rand"
	"errors"
	"mime"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"sync"

	"gitlab.com/gopherburrow/cookie"
	"gitlab.com/gopherburrow/jwt"
)

const defaultKeySize = 32

const (
	//DefaultName stores the default cookie name that will be used if no csrfcookie.Config.SetName() method is called.
	DefaultName = "csrf-token"
	//DefaultFormFieldName stores the default form field name that will be used if no csrfcookie.Config.SetFormFieldName() method is called.
	DefaultFormFieldName = "csrf-token"
	//DefaultHeaderName stores the default header name that will be used if no csrfcookie.Config.SetHeaderName() method is called.
	DefaultHeaderName = "X-CSRF-Token"
)

// Errors returned in method input validations.
var (
	//ErrNameMustBeValid is returned in SetName(name) method when name is invalid.
	ErrNameMustBeValid = errors.New("csrfcookie: cookie name must be valid")
	//ErrDomainMustBeValid is returned in SetDomain(domain) method when domain is invalid.
	ErrDomainMustBeValid = errors.New("csrfcookie: cookie domain must be valid (a domain with at least 2 parts prefixed with '.' or a IP address are valid values)")
	//ErrPathMustBeValid is returned in SetPath(path) method when path is invalid.
	ErrPathMustBeValid = errors.New("csrfcookie: cookie path must be valid")
	//ErrFormFieldNameMustBeValid is returned in SetFormFieldName(name) method when name is invalid.
	ErrFormFieldNameMustBeValid = errors.New("csrfcookie: form field name must be valid")
	//ErrHeaderNameMustBeValid is returned in SetHeaderName(name) method when name is invalid.
	ErrHeaderNameMustBeValid = errors.New("csrfcookie: CSRF header name must be valid")
)

//Errors caused by misconfiguration or implementation fault while serving a request.
var (
	//ErrMustUseTLS is returned if a non TLS request is received.
	ErrMustUseTLS = errors.New("csrfcookie: CSRF protection requires TLS")
	//ErrCookieDomainMustMatch is returned when the a request is made to a domain that
	//it will not be able to receive the cookie because the cookie domain is set to a different and incompatible domain than the requested.
	ErrDomainMustMatchRequest = errors.New("csrfcookie: CSRF protection cookie domain must match request domain")
	//ErrCookiePathMustMatch is returned when a request is made to a path that
	//it will not be able to receive the cookie because the cookie path is set to to a different and incompatible path than the requested.
	ErrPathMustMatchRequest = errors.New("csrfcookie: CSRF protection cookie path must match request path")
	//ErrClaimsMustBeNotEmpty ir returned when claims are nil or empty in Create() method.
	ErrClaimsMustBeNotEmpty = errors.New("csrfcookie: claims must be not empty")
	//ErrSecretError is returned when the csrfcookie.Config.SecretFunc is set but it returned a empty secret.
	ErrSecretError = errors.New("csrfcookie: the CSRF token secret cannot be empty")
)

//Errors caused by a malformed or malicious request when serving a request in ServeHTTP() method.
var (
	//ErrOriginMustMatchRequest is returned when the Origin Header is present (Firefox not send it) and it does not match the request host.
	ErrOriginMustMatchRequest = errors.New("csrfcookie: Origin header does not match the request host (possible CSRF attack)")
	//ErrRequestMustHaveReferer is returned when the Referer Header was not found in the request.
	ErrRequestMustHaveReferer = errors.New("csrfcookie: Referer header was not found (possible CSRF attack)")
	//ErrRefererMustMatchRequest is returned when the Referer Header does not match the request host.
	ErrRefererMustMatchRequest = errors.New("csrfcookie: Referer header does not match the request host (possible CSRF attack)")
	//ErrRefererMustMatchCookieDomain is returned when the Referer Header does not match the cookie domain set in CSRF Cookie Token.
	//That means that even if the Referer Header and the host are not the same, but have a common set suffix they can share the CSRF Token, an could be considered same site.
	ErrRefererMustMatchCookieDomain = errors.New("csrfcookie: Referer header does not match the cookie domain configuration (possible CSRF attack)")
	//ErrRefererMustMatchCookiePath is returned when the Referer Header does not match the cookie path set in CSRF Cookie Token.
	//That means that even if the Referer Header and the host are the same, the request was configured as another Site, so it is handled like a Cross-Site-Request.
	ErrRefererMustMatchCookiePath = errors.New("csrfcookie: Referer header does not match the cookie path configuration (possible CSRF attack)")
	//ErrOriginAndRefererMustMatch is returned when the Origin Header (when present) does not match the Referer Header.
	ErrOriginAndRefererMustMatch = errors.New("csrfcookie: Origin and Referer header must match (possible CSRF attack)")
	//ErrMustBeUnique is returned when the CSRF protection cookie is not unique.
	//If there is no Custom ErrorHandler and this error occurs the server will send a lots Cookie Deletion (Max-Age=0) to the browser to avoid unrecoverable CSRF errors.
	ErrMustBeUnique = errors.New("csrfcookie: CSRF protection cookie not unique (possible CSRF attack)")
	//ErrNotFound is returned when the CSRF protection cookie is not found in the request.
	ErrNotFound = errors.New("csrfcookie: CSRF protection cookie not found (possible CSRF attack)")
	//ErrTokenValuesMustMatch is returned when the value from the CSRF Token cookie does not match the form field value. This is the most common case for a CSRF attack.
	ErrTokenValuesMustMatch = errors.New("csrfcookie: CSRF cookie and token values must match (possible CSRF attack)")
	//ErrTokenSignatureMustMatch is returned when the CSRF protection cookie and form values are received, but the signature is not valid or is tampered.
	ErrTokenSignatureMustMatch = errors.New("csrfcookie: CSRF token signature does not match (possible CSRF attack)")
)

//ErrRequestMustBeXWwwFormURLEncoded is returned when using ValidateWithForm() and the request not came from a HTML Form.
var ErrRequestMustBeXWwwFormURLEncoded = errors.New("csrfcookie: only application/x-www-form-urlencoded content type is supported")

//ErrCannotReadFormValues is returned when the Form values cannot be read from the request Body.
var ErrCannotReadFormValues = errors.New("csrfcookie: form values cannot be read")

//Config stores the configuration for a set of HTTP resources that will be protected against CSRF attacks.
type Config struct {
	//SecretFunc is a function that will be used to create the secret for the HMAC-SHA256 signature for the CSRF Token JWT.
	//It can be used to rotate the secret, shared the between multiple instances of a Handler or even multiple server instances.
	//It MUST return a non nil and not empty secret.
	SecretFunc func(r *http.Request) []byte

	secret     []byte
	secretOnce sync.Once
	//cookieName stores a custom user defined cookie name used to store the CSRF Token.
	//It can only be set in SetName(name) method.
	cookieName string
	//cookieDomain stores a custom user defined cookie domain used to store the CSRF Token.
	//It can only be set in SetDomain(domain) method.
	cookieDomain string
	//cookiePath stores a custom user defined cookie path used to store the CSRF Token.
	//It can only be set in SetPath(path) method.
	cookiePath string
	//formFieldName stores a custom user defined form field name that will be matched against the cookie CSRF Token.
	//It can be set in SetFormFieldName(formFieldName) method.
	formFieldName string
	//headerName stores a custom user defined CSRF token header name that will be matched against the cookie CSRF Token.
	//It can be set in SetHeaderName(name) method.
	headerName string
}

//SetCookieName sets the Cookie name used for CSRF Protection.
//
//Use when there are diferent Handlers on same server. So Cookies will not conflict.
//
//If name is valid nil will be returned, otherwise csrfcookie.ErrNameMustBeValid will be returned.
func (c *Config) SetCookieName(v string) error {
	if !cookie.ValidName(v) {
		return ErrNameMustBeValid
	}
	c.cookieName = v
	return nil
}

//SetCookieDomain sets the Cookie domain used for CSRF Protection.
//
//Use to SHARE the CSRF Protection between applications that share a domain suffix.
//
//If domain is valid ('.'+domainNameWithTwoParts) or IP address) nil will be returned, otherwise csrfcookie.ErrDomainMustBeValid will be returned.
//
//It requires the leading '.' so the behavior of cookies (The browser puts the leading '.' if its missing) is unambiguous.
//
//It requires at least a domain name with 2 parts to avoid unexpected behavior, because the browsers do not store cookies on root domains.
func (c *Config) SetCookieDomain(v string) error {
	if !cookie.ValidDomain(v) {
		return ErrDomainMustBeValid
	}
	c.cookieDomain = v
	return nil
}

//SetCookiePath sets the Cookie domain used for CSRF Protection.
//
//Use to ISOLATE the CSRF Protection between applications that share the same domain but use different path suffixes.
//
//If path is valid, nil will be returned, otherwise csrfcookie.ErrPathMustBeValid will be returned.
func (c *Config) SetCookiePath(v string) error {
	if !cookie.ValidPath(v) {
		return ErrPathMustBeValid
	}
	c.cookiePath = v
	return nil
}

//SetFormFieldName sets the HTML form field name used for CSRF Protection.
//
//The form field value identified by this name will be checked against the cookie in POST, PUT and DELETE requests.
//
//Use to avoid form fields name conflicts in some situations.
//
//If name is valid, nil will be returned, otherwise csrfcookie.ErrFormFieldNameMustBeValid will be returned.
func (c *Config) SetFormFieldName(name string) error {
	if !cookie.ValidName(name) {
		return ErrFormFieldNameMustBeValid
	}
	c.formFieldName = name
	return nil
}

//SetHeaderName sets the HTTP header name used for CSRF Protection.
//
//The header value identified by this name will be checked against the cookie in POST, PUT and DELETE requests.
//
//Use to avoid conflicts in some situations or integrate with some client-side frameworks.
//
//If name is valid, nil will be returned, otherwise csrfcookie.ErrHeaderNameMustBeValid will be returned.
//
//Valid names are MIME header names. That is: Hyphen-Sign-Separated-Ascii-Words-With-First-Capital-Letters.
func (c *Config) SetHeaderName(name string) error {
	if !strings.HasPrefix(name, "X-") || textproto.CanonicalMIMEHeaderKey(name) != name {
		return ErrHeaderNameMustBeValid
	}
	c.headerName = name
	return nil
}

//ValidateWithForm validates the CSRF Token in the form.
func ValidateWithForm(c *Config, r *http.Request) error {
	//There is no necessity to protect a nullipotent request. Skip the validation.
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodTrace || r.Method == http.MethodOptions {
		return nil
	}

	//Test the common token validation.
	if err := validateCommonParts(c, r); err != nil {
		return err
	}

	//For this specific handler, be a HTML Form request are a prerequisite for non-nulipotent requests.
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		return ErrRequestMustBeXWwwFormURLEncoded
	}

	//Read the form fields and retrieve the specific CSRF TOKEN field name, checking all the errors in the process.
	err = r.ParseForm()
	if err != nil {
		return ErrCannotReadFormValues
	}
	formFieldName := c.formFieldName
	if formFieldName == "" {
		formFieldName = DefaultFormFieldName
	}
	formCsrfToken := r.PostForm.Get(formFieldName)

	//Check the if token value match and is correctly signed.
	if err := checkTokenValue(c, r, formCsrfToken); err != nil {
		return err
	}

	//It is an authentic same-site validated request. Go get your prize.
	return nil
}

//ValidateWithHeader validates the CSRF Token in the header.
func ValidateWithHeader(c *Config, r *http.Request) error {

	//There is no necessity to protect a nullipotent request. Skip the validation.
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodTrace || r.Method == http.MethodOptions {
		return nil
	}

	//Test the common token validation.
	if err := validateCommonParts(c, r); err != nil {
		return err
	}

	//Read the form fields and retrieve the specific CSRF TOKEN field name, check all the errors in the process.
	headerName := c.headerName
	if headerName == "" {
		headerName = DefaultHeaderName
	}
	headerCsrfToken := r.Header.Get(headerName)

	//Check the if token value match and is correctly signed.
	if err := checkTokenValue(c, r, headerCsrfToken); err != nil {
		return err
	}

	//It is an authentic same-site validated request. Go get your prize.
	return nil
}

//Create a CSRF Token Cookie
//
//a nonce value in claims must be a short-lived value to avoid replay attacks. Normally a session long nonce expiry time is enough.
func Create(c *Config, r *http.Request, claims map[string]interface{}) (string, *http.Cookie, error) {
	if claims == nil || len(claims) == 0 {
		return "", nil, ErrClaimsMustBeNotEmpty
	}

	//Recover the secret handling errors.
	s, err := secret(c, r)
	if err != nil {
		return "", nil, err
	}

	//Create the signed token, if there is an error return it.
	//NO ERROR occurrence here.
	jwt, _ := jwt.CreateHS256(claims, s)

	//Create the cookie using the Handler settings and return it.
	cookieName := c.cookieName
	if cookieName == "" {
		cookieName = DefaultName
	}
	cookie := &http.Cookie{
		Name:     cookieName,
		Value:    jwt,
		Secure:   true,
		HttpOnly: true,
		Domain:   c.cookieDomain,
		Path:     c.cookiePath,
	}
	return jwt, cookie, nil
}

//Value returns the form field value used for CSRF Protection.
//
//Use to embed together with FormFieldName in forms.
//
//TODO
//It will return an ErrNotFound error if CSRF cookie is not found.
//
//It will return an ErrRequestMustHaveContext error if called outside Handler.Handler stacktrace.
func Value(c *Config, r *http.Request) (string, error) {
	name := c.cookieName
	if name == "" {
		name = DefaultName
	}

	cookie, err := r.Cookie(name)

	if err == http.ErrNoCookie || cookie == nil {
		return "", ErrNotFound
	}

	return cookie.Value, nil
}

//TODO Nonce Method. Probably necessary to compare with session token.

//Delete returns a Cookie with MaxAge 0, that commands the browser to delete the CSRF Cookie.
//
//Use it to finish a CSRF Session.
//
//Notice that the JWT token is still valid even after this method is called.
//So a external functionality, like CSRF Token revocation or a linked Session Token validation is needed to ensure no replay attacks are used.
func DeleteCookie(c *Config) *http.Cookie {
	//Retrieve the custom or default cookie name.
	cookieName := c.cookieName
	if cookieName == "" {
		cookieName = DefaultName
	}

	//A cookie with MaxAge=-1 (MaxAge 0 is sent in HTTP) is a command to browser to delete the cookie.
	cookie := &http.Cookie{
		Name:     cookieName,
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		Domain:   c.cookieDomain,
		Path:     c.cookiePath,
	}

	//Send the cookie in response.
	return cookie
}

//validateCommonParts the common token validation in form or header CSRF.
func validateCommonParts(c *Config, r *http.Request) error {
	//Check all cookie request prerequisites.
	if err := checkCookieTLSDomainAndPath(c, r); err != nil {
		return err
	}

	//Check the basic CSRF aware headers and their compliance with the cookie config.
	if err := checkOriginAndReferer(c, r); err != nil {
		return err
	}

	//No common errors were found.
	return nil
}

func checkCookieTLSDomainAndPath(c *Config, r *http.Request) error {
	//Only TLS requests are really protected by CSRF token protection. So deny non TLS requests.
	if r.TLS == nil {
		return ErrMustUseTLS
	}

	//Only can serve requests that the cookie domains allowed or it will never receive the CSRF Protextion Cookie. Normally a configuration error.
	if c.cookieDomain != "" && r.Host != c.cookieDomain[1:] && !strings.HasSuffix(r.Host, c.cookieDomain) {
		return ErrDomainMustMatchRequest
	}

	//The same is valid for the cookie path. Only can serve requests that the cookie path allowed it to receive the cookie.
	if c.cookiePath != "" && c.cookiePath != r.URL.Path && !strings.HasPrefix(strings.TrimRight(r.URL.Path, "/")+"/", strings.TrimRight(c.cookiePath, "/")+"/") {
		return ErrPathMustMatchRequest
	}

	//No errors
	return nil
}

//checkOriginAndReferer returns a error if a CSRF attack was found in these Origin and Referer HTTP headers.
func checkOriginAndReferer(c *Config, r *http.Request) error {
	//Check Both Origin and Referer match the Request.
	if err := checkOrigin(c, r); err != nil {
		return err
	}
	if err := checkReferer(c, r); err != nil {
		return err
	}

	//Check if Origin and Referer Headers match.
	origin := r.Header.Get("Origin")
	referer := r.Referer()
	if origin != "" && referer != origin && !strings.HasPrefix(strings.TrimRight(referer, "/")+"/", strings.TrimRight(origin, "/")+"/") {
		return ErrOriginAndRefererMustMatch
	}
	return nil
}

//checkOrigin returns a error if a CSRF attack was found in Origin HTTP header.
func checkOrigin(c *Config, r *http.Request) error {

	//Check Origin header only if it is present (because it is not mandatory and Firefox does not send it).
	o := r.Header.Get("Origin")
	if o == "" { //Before Firefox 59, it was only sent in CORS requests. Maybe test Agent Header?
		return nil
	}

	//In the case Origin is exactly the same domain target, it is valid for any purposes.
	if o == "https://"+r.Host {
		return nil
	}

	//Origin != target and no domain set. Use the strict rules...
	if c.cookieDomain == "" {
		return ErrOriginMustMatchRequest
	}

	//Parse the Origin URL (an error is considered a mismatch) and check if it is https.
	oURL, err := url.Parse(o)
	if err != nil || oURL.Scheme != "https" { //FIXME Maybe Chrome send it when http.
		return ErrOriginMustMatchRequest
	}

	//...but if there is a cookie domain set, loosen the rules and allow it to compare with the suffix too.
	//Bonus if o is not a root(/) absolute https URL this will fail too.
	if o != "https://"+c.cookieDomain[1:] && !strings.HasSuffix(o, c.cookieDomain) {
		return ErrOriginMustMatchRequest
	}

	return nil
}

//checkReferer returns a error if a CSRF attack was found in Referer HTTP header.
func checkReferer(c *Config, r *http.Request) error {
	//Referer always is present from a, possible, GET before the form submission or a form retry from a POST.
	//So if it is missing, it came directly from the URL (that is no even possible clicking in a link or bookmark) bar or a CSRF attack.
	ref := r.Referer()
	if ref == "" {
		return ErrRequestMustHaveReferer
	}

	//Parse the referer URL (an error is considered a mismatch) and check if it is https.
	refURL, err := url.Parse(ref)
	if err != nil || refURL.Scheme != "https" {
		return ErrRefererMustMatchRequest
	}

	//If referer domain is the same as the target, it is always valid (with domain or not) Skip these tests...
	if refURL.Host != r.Host {
		// ... If no domain set. Using the strict rules, this is an error...
		if c.cookieDomain == "" {
			return ErrRefererMustMatchRequest
		}
		//If there is a cookie domain set, loosen the rules and allow it to compare with the suffix too.
		if refURL.Host != c.cookieDomain[1:] && !strings.HasSuffix(refURL.Host, c.cookieDomain) {
			return ErrRefererMustMatchCookieDomain
		}
	}

	//If case there is a cookie path set, stricten the rules based on a path prefix.
	if c.cookiePath != "" && c.cookiePath != refURL.Path && !strings.HasPrefix(strings.TrimRight(refURL.Path, "/")+"/", strings.TrimRight(c.cookiePath, "/")+"/") {
		return ErrRefererMustMatchCookiePath
	}
	return nil
}

func checkTokenValue(c *Config, r *http.Request, requestToken string) error {
	//Retrieve the CSRF token value from cookie checking if it exists.
	cookieName := c.cookieName
	if cookieName == "" {
		cookieName = DefaultName
	}

	//Find the CSRF Cookie assuring it is unique.
	//To avoid nasty bugs on users, delete if it is not unique(That is the reason not use r.Cookie(name)).
	//It can happens when a cookie domain is added or changed.
	var cookie *http.Cookie
	for _, ac := range r.Cookies() {
		if ac.Name != cookieName {
			continue
		}

		if cookie != nil {
			return ErrMustBeUnique
		}
		cookie = ac
	}
	if cookie == nil {
		return ErrNotFound
	}
	cookieCsrfToken := cookie.Value

	//Check if tokens match.
	if requestToken != cookieCsrfToken {
		return ErrTokenValuesMustMatch
	}

	//Recover the secret handling errors.
	s, err := secret(c, r)
	if err != nil {
		return err
	}

	//Test if it is ours token (verifying the signature), and not a token created by an attacker.
	if _, err := jwt.ValidateHS256(cookieCsrfToken, s); err != nil {
		return ErrTokenSignatureMustMatch
	}

	return nil
}

func secret(c *Config, r *http.Request) ([]byte, error) {
	//Retrieve the Token secret (Custom). Handle errors.
	if c.SecretFunc != nil {
		secret := c.SecretFunc(r)
		//It is part of the contract. Never return an empty secret. (Because it is no secret that way.)
		if secret == nil || len(secret) == 0 {
			return nil, ErrSecretError
		}
		return secret, nil
	}

	//If a default secret was already created, return it.
	if c.secret != nil {
		return c.secret, nil
	}

	c.secretOnce.Do(func() {
		c.secret = make([]byte, defaultKeySize)
		rand.Read(c.secret)
	})

	return c.secret, nil
}
