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
//Warning: The security mechanism utilized by this package is not able to protect from CSRF if there is a XSS (Cross Site Scripting) flaw in the pages served by the Handler.
//
//This implementation does not support more than one Handler (Form or API) in the same Handler chain.
//
//Double-Submit-Cookie
//
//In a server state changing operation (POST, PUT or DELETE), a previously created cookie value is checked against a form field or user HTTP header value.
//
//More information to Double-Submit-Cookie can be found at https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Double_Submit_Cookie .
package csrfcookie

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"

	"gitlab.com/gopherburrow/cookie"
	"gitlab.com/gopherburrow/jwt"
)

const (
	//DefaultName stores the default cookie name that will be used if no csrfcookie.Config.SetName() method is called.
	DefaultName = "csrf-token"
	//DefaultHeaderName stores the default header name that will be used if no csrfcookie.Config.SetHeaderName() method is called.
	DefaultHeaderName    = "X-CSRF-Token"
	defaultFormFieldName = "csrf-token"
	ctxHandlerValue      = "gitlab.com/gopherburrow/csrfcookie Handler"
	ctxErrorValue        = "gitlab.com/gopherburrow/csrfcookie Error"
)

//Used in request contexts. Go suggests using a specific type different from string for context keys.
type ctxType string

//The key used to store the Handler used in CSRF cookie handling.
//So it is possible to call Create and Value methods inside the served delegated Handlers.
var ctxHandler = ctxType(ctxHandlerValue)

//The key used to store the error used in CSRF cookie handling.
//So it is possible to retrieve it inside a ErrorHandler.
var ctxError = ctxType(ctxErrorValue)

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
	//ErrConfigMustBeNonNil is returned in NewFormHandler and NewApiHandler method when the c parameter is nil.
	ErrConfigMustBeNonNil = errors.New("csrfcookie: config must be non nil")
	//ErrHandlerMustBeNotNil is returned in NewFormHandler and NewApiHandler method when the chain parameter is nil.
	ErrChainHandlerMustBeNonNil = errors.New("csrfcookie: chain handler must be non nil")
	//ErrErrorCreatingSecret is returned when an inexpected error happened during token secret creation in NewFormHandler() or NewAPIHandler methods.
	ErrErrorCreatingSecret = errors.New("csrfcookie: an error happened while creating the CSRF token secret")
)

//WebError is a class of errors launched in requests from NewFormHandler and NewAPIHandler that trigger a Config.ErrorHandler call.
//They can be retrieved with csrfcookie.Error()
type WebError struct {
	//HTTPStatusCode is returned by the default error handler when a WebError occurs.
	//It can be used by Custom csrfcookie.Config.ErrorHandler's to maintain the default returned HTTP status codes,
	//using csrfcookie.Error().HTTPStatusCode inside the ErrorHandler call.
	//It can be used to change the default status code for the errors.
	//Eg: csrfcookie.ErrOriginMustMatchRequest.HTTPStatusCode = http.StatusBadRequest
	HTTPStatusCode int
	//s holds the error message.
	s string
}

//Error implements the error interface for WebError.
func (e *WebError) Error() string {
	return e.s
}

//Errors caused by misconfiguration or implementation fault when serving a request in ServeHTTP() method.
//
//These errors can be captured using the Error() method when inside an ErrorHandler.
//
//If not custom-handled using ErrorHandler these errors will return a "500 - Internal Server Error" page.
var (
	//ErrRequestMustHaveContext is returned by FormFieldName(), Value(), Create(), Delete() and Error() methods when there is no context found in request.
	ErrRequestMustHaveContext = &WebError{http.StatusInternalServerError, "csrfcookie: context not found (request must came from a csrfcookie.Handler)"}
	//ErrMustUseTLS is returned if a non TLS request is received by Handler.
	ErrMustUseTLS = &WebError{http.StatusInternalServerError, "csrfcookie: CSRF protection requires TLS"}
	//ErrCookieDomainMustMatch is returned when the Handler serves a request to a domain that
	//it will not be able to receive the cookie because the cookie domain is set to another domain than the served one.
	ErrDomainMustMatchRequest = &WebError{http.StatusInternalServerError, "csrfcookie: CSRF protection cookie domain must match request domain"}
	//ErrCookiePathMustMatch is returned when the Handler serves a request to a path that
	//it will not be able to receive the cookie because the cookie path is set to another path than the served one.
	ErrPathMustMatchRequest = &WebError{http.StatusInternalServerError, "csrfcookie: CSRF protection cookie path must match request path"}
	//ErrClaimsMustBeNotEmpty ir returned when claims are nil or empty in Create() method.
	ErrClaimsMustBeNotEmpty = &WebError{http.StatusInternalServerError, "csrfcookie: claims must be not empty"}
	//ErrSecretError is returned when the csrfcookie.Handler.SecretFunc is set but it returned a empty secret.
	ErrSecretError = &WebError{http.StatusInternalServerError, "csrfcookie: the CSRF token secret cannot be empty"}
)

//Errors caused by a malformed or malicious request when serving a request in ServeHTTP() method.
//
//These errors can be captured using the Error() method when inside an ErrorHandler.
//
//If not custom-handled using ErrorHandler these errors will return a "403 - Forbidden page.
var (
	//ErrOriginMustMatchRequest is returned when the Origin Header is present (Firefox not send it) and it does not match the request host.
	ErrOriginMustMatchRequest = &WebError{http.StatusForbidden, "csrfcookie: Origin header does not match the request host (possible CSRF attack)"}
	//ErrRequestMustHaveReferer is returned when the Referer Header was not found in the request.
	ErrRequestMustHaveReferer = &WebError{http.StatusForbidden, "csrfcookie: Referer header was not found (possible CSRF attack)"}
	//ErrRefererMustMatchRequest is returned when the Referer Header does not match the request host.
	ErrRefererMustMatchRequest = &WebError{http.StatusForbidden, "csrfcookie: Referer header does not match the request host (possible CSRF attack)"}
	//ErrRefererMustMatchCookieDomain is returned when the Referer Header does not match the cookie domain set in CSRF Cookie Token.
	//That means that even if the Referer Header and the host are not the same, but have a common set suffix they can share the CSRF Token, an could be considered same site.
	ErrRefererMustMatchCookieDomain = &WebError{http.StatusForbidden, "csrfcookie: Referer header does not match the cookie path Handler configuration (possible CSRF attack)"}
	//ErrRefererMustMatchCookiePath is returned when the Referer Header does not match the cookie path set in CSRF Cookie Token.
	//That means that even if the Referer Header and the host are the same, the request was configured as another Site, so it is handled like a Cross-Site-Request.
	ErrRefererMustMatchCookiePath = &WebError{http.StatusForbidden, "csrfcookie: Referer header does not match the cookie path Handler configuration (possible CSRF attack)"}
	//ErrOriginAndRefererMustMatch is returned when the Origin Header (when present) does not match the Referer Header.
	ErrOriginAndRefererMustMatch = &WebError{http.StatusForbidden, "csrfcookie: Origin and Referer header must match (possible CSRF attack)"}
	//ErrMustBeUnique is returned when the CSRF protection cookie is not unique.
	//If there is no Custom ErrorHandler and this error occurs the server will send a lots Cookie Deletion (Max-Age=0) to the browser to avoid unrecoverable CSRF errors.
	ErrMustBeUnique = &WebError{http.StatusForbidden, "csrfcookie: CSRF protection cookie not unique (possible CSRF attack)"}
	//ErrNotFound is returned when the CSRF protection cookie is not found in the request.
	ErrNotFound = &WebError{http.StatusForbidden, "csrfcookie: CSRF protection cookie not found (possible CSRF attack)"}
	//ErrTokenValuesMustMatch is returned when the value from the CSRF Token cookie does not match the form field value. This is the most common case for a CSRF attack.
	ErrTokenValuesMustMatch = &WebError{http.StatusForbidden, "csrfcookie: CSRF cookie and form values must match (possible CSRF attack)"}
	//ErrTokenSignatureMustMatch is returned when the CSRF protection cookie and form values are received, but the signature is not valid or is tampered.
	//If there is no Custom ErrorHandler and this error occurs the server will send a Cookie Deletion (Max-Age=0) to the browser.
	ErrTokenSignatureMustMatch = &WebError{http.StatusForbidden, "csrfcookie: CSRF token signature does not match (possible CSRF attack)"}
)

//ErrRequestMustBeXWwwFormURLEncoded is returned when using csrfcookie.Config.NewFormHandler() and the request not came from a HTML Form.
//If not custom-handled using ErrorHandler this error will return a "415 - Unsupported Media Type".
var ErrRequestMustBeXWwwFormURLEncoded = &WebError{http.StatusUnsupportedMediaType, "csrfcookie: only application/x-www-form-urlencoded content type is supported"}

//ErrCannotReadFormValues is returned when the Form values cannot be read from the request Body.
//If not custom-handled using ErrorHandler this error will return a "400 - Bad Request".
var ErrCannotReadFormValues = &WebError{http.StatusBadRequest, "csrfcookie: form values cannot be read"}

//Config stores the configuration for a set of HTTP resources that will be protected against CSRF attacks.
type Config struct {
	//SecretFunc is a function that will be used to create the secret for the HMAC-SHA256 signature for the CSRF Token JWT.
	//It can be used to rotate the secret, shared the between multiple instances of a Handler or even multiple server instances.
	//It MUST not return a nil secret or an empty one.
	SecretFunc func(r *http.Request) []byte
	//ErrorHandler will be called if a CSRF Protection or an implementation check fail in a POST, PUT or DELETE.
	//If nil, the WebError.HTTPStatusCode will be used(normally a vaniilla 403 - Forbidden or 500 - Internal Server Error will be served depending on error).
	ErrorHandler http.Handler
	//name stores a custom user defined cookie name used to store the CSRF Token.
	//It can only be set in SetName(name) method.
	name string
	//domain stores a custom user defined cookie domain used to store the CSRF Token.
	//It can only be set in SetDomain(domain) method.
	domain string
	//path stores a custom user defined cookie path used to store the CSRF Token.
	//It can only be set in SetPath(path) method.
	path string
	//formFieldName stores a custom user defined form field name that will be matched against the cookie CSRF Token.
	//It can be set in SetFormFieldName(formFieldName) method.
	formFieldName string
	//headerName stores a custom user defined CSRF token header name that will be matched against the cookie CSRF Token.
	//It can be set in SetHeaderName(name) method.
	headerName string
}

//SetName sets the Cookie name used for CSRF Protection.
//
//Use when there are diferent Handlers on same server. So Cookies will not conflict.
//
//If name is valid nil will be returned, otherwise csrfcookie.ErrNameMustBeValid will be returned.
func (c *Config) SetName(name string) error {
	if !cookie.ValidName(name) {
		return ErrNameMustBeValid
	}
	c.name = name
	return nil
}

//SetDomain sets the Cookie domain used for CSRF Protection.
//
//Use to SHARE the CSRF Protection between applications that share a domain suffix.
//
//If domain is valid ('.'+domainNameWithTwoParts) or IP address) nil will be returned, otherwise csrfcookie.ErrDomainMustBeValid will be returned.
//
//It requires the leading '.' so the behavior of cookies (The browser puts the leading '.' if its missing) becames very clear.
//
//It requires at least a domain name with 2 parts to avoid unexpected behavior, because the browsers do not store cookies on root domains.
func (c *Config) SetDomain(domain string) error {
	if !cookie.ValidDomain(domain) {
		return ErrDomainMustBeValid
	}
	c.domain = domain
	return nil
}

//SetPath sets the Cookie domain used for CSRF Protection.
//
//Use to ISOLATE the CSRF Protection between applications that share the same domain but use different path suffixes.
//
//If path is valid, nil will be returned, otherwise csrfcookie.ErrPathMustBeValid will be returned.
func (c *Config) SetPath(path string) error {
	if !cookie.ValidPath(path) {
		return ErrPathMustBeValid
	}
	c.path = path
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

//formHandler is an `http.Handler` that implements a CSRF Protection mechanism.
type formHandler struct {
	config *Config
	//chain is the handler that will be called if all CSRF Protection checks passed or is a GET, OPTIONS, HEAD or TRACE.
	chain http.Handler
}

//NewFormHandler returns a new `http.Handler` that implements a CSRF Protection mechanism for normal HTML form submissions.
//
//The returned handler dispatches POST, PUT or DELETE requests, protecting them against Cross-Site-Request-Forgery attacks,
//and prepare (and dispatch too) GET (and others) requests to Create, when necessary, the CSRF Protection Token.
//
//It checks if the Origin and Referer Headers are the same than the action URL in the form and, after that, check the Double-Submit-Cookie pattern using a cookie value and a form field value.
//
//If a error happens (internal or user generated) when dispatching requests, the ErrorHandler from csrfcookie.Config will be called (or a default error handler if not set).
//There, inside the handler, it is possible to retrieve the specific error using the csrfcookie.Error() method.
//
//If no error happens, the chain handler will be called instead.
//Inside the chain handler it is possible to use the csrfcookie.Create(), csrfcookie.FormFieldName(), csrfcookie.Value() and csrfcookie.Delete() methods.
//
//Notice: This Handler is specifically tailored to work with normal HTML form submissions and server side created pages. It is no suited for JSON Based APIs or SOAP Requests.
//
//If c and chain is valid, nil will be returned.
//If c is nil csrfcookie.ErrConfigMustBeNonNil will be returned.
//If chain is nil csrfcookie.ErrChainHandlerMustBeNonNil will be returned.
func NewFormHandler(c *Config, chain http.Handler) (http.Handler, error) {
	//Handle Input errors.
	if c == nil {
		return nil, ErrConfigMustBeNonNil
	}
	if chain == nil {
		return nil, ErrChainHandlerMustBeNonNil
	}

	//Return the decorator handler.
	return &formHandler{
		config: c,
		chain:  chain,
	}, nil
}

func validateFormToken(c *Config, r *http.Request) *WebError {
	if err := checkPrerequisites(c, r); err != nil {
		return err
	}

	//There is no necessity to protect a nullipotent request.
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodTrace || r.Method == http.MethodOptions {
		return nil
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

	//Check the basic CSRF aware headers and their compliance with the cookie config.
	if err := checkOriginAndReferer(c, r); err != nil {
		return err
	}

	//Read the form fields and retrieve the specific CSRF TOKEN field name, check all the errors in the process.
	err = r.ParseForm()
	if err != nil {
		return ErrCannotReadFormValues
	}
	formFieldName := c.formFieldName
	if formFieldName == "" {
		formFieldName = defaultFormFieldName
	}
	formCsrfToken := r.PostForm.Get(formFieldName)

	//Check the if token value match and is correctly signed.
	if err := checkTokenValue(c, r, formCsrfToken); err != nil {
		return err
	}

	//It is an authentic same-site validated request. Go get your prize.
	return nil
}

//ServeHTTP makes formHandler implement the http.Handler interface.
func (fh *formHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := validateFormToken(fh.config, r); err != nil {
		errorHandler(fh.config, err, w, r)
		return
	}

	//It is an authentic same-site validated request. Go get your prize.
	fh.chain.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxHandler, fh.config)))
	return
}

//formHandler is an `http.Handler` that implements a CSRF Protection mechanism.
type apiHandler struct {
	config *Config
	//chain is the handler that will be called if all CSRF Protection checks passed or is a GET, OPTIONS, HEAD or TRACE.
	chain http.Handler
}

//NewAPIHandler returns a new `http.Handler` that implements a CSRF Protection mechanism REST APIs.
//
//The returned handler dispatches POST, PUT or DELETE requests, protecting them against Cross-Site-Request-Forgery attacks,
//and prepare (and dispatch too) GET (and others) requests to create (using csrfcookie.Create() method), when necessary, the CSRF Protection Token.
//
//It checks if the Origin and Referer Headers are the compatible with the request URL, after that, check the Double-Submit-Cookie pattern using a cookie value and a custom HTTP Header value.
//
//If a error happens (internal or user generated) when dispatching requests, the ErrorHandler from csrfcookie.Config will be called (or a default error handler if not set).
//There, inside the handler, it is possible to retrieve the specific error using the csrfcookie.Error() method.
//
//If no error happens, the chain handler will be called instead.
//Inside the chain handler it is possible to use the csrfcookie.Create(), csrfcookie.FormFieldName(), csrfcookie.Value() and csrfcookie.Delete() methods.
//
//Notice: This Handler is specifically tailored to work with REST APIs requests. It is no suited for normal HTML form submissions.
//
//If c and chain is valid, nil will be returned.
//If c is nil csrfcookie.ErrConfigMustBeNonNil will be returned.
//If chain is nil csrfcookie.ErrChainHandlerMustBeNonNil will be returned.
func NewAPIHandler(c *Config, chain http.Handler) (http.Handler, error) {
	//Handle Input errors.
	if c == nil {
		return nil, ErrConfigMustBeNonNil
	}
	if chain == nil {
		return nil, ErrChainHandlerMustBeNonNil
	}

	//Return the decorator handler.
	return &apiHandler{
		config: c,
		chain:  chain,
	}, nil
}

func validateHeaderToken(c *Config, r *http.Request) *WebError {
	if err := checkPrerequisites(c, r); err != nil {
		return err
	}

	//There is no necessity to protect a nullipotent request.
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodTrace || r.Method == http.MethodOptions {
		return nil
	}

	//Check the basic CSRF aware headers and their compliance with the cookie config.
	if err := checkOriginAndReferer(c, r); err != nil {
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

//ServeHTTP makes apiHandler implement the http.Handler interface.
func (fh *apiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := validateHeaderToken(fh.config, r); err != nil {
		errorHandler(fh.config, err, w, r)
		return
	}

	//It is an authentic same-site validated request. Go get your prize.
	fh.chain.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxHandler, fh.config)))
	return
}

//Create a CSRF Token Cookie, put it on Response Headers and return it value.
//
//nonce must be a short-lived value to avoid replay attacks. Normally a session long nonce expiry time is enough.
func Create(w http.ResponseWriter, r *http.Request, claims map[string]interface{}) (string, *WebError) {
	c, ok := r.Context().Value(ctxHandler).(*Config)
	if !ok {
		return "", ErrRequestMustHaveContext
	}

	if claims == nil || len(claims) == 0 {
		return "", ErrClaimsMustBeNotEmpty
	}

	//Recover the secret handling errors.
	s, err := secret(c, r)
	if err != nil {
		return "", err
	}

	//Create the signed token, if there is an error return it.
	//NO ERROR occurrence here.
	jwt, _ := jwt.CreateHS256(claims, s)

	//Create the cookie using the Handler settings and return it.
	name := c.name
	if name == "" {
		name = DefaultName
	}
	cookie := &http.Cookie{
		Name:     name,
		Value:    jwt,
		Secure:   true,
		HttpOnly: true,
		Domain:   c.domain,
		Path:     c.path,
	}
	http.SetCookie(w, cookie)
	return jwt, nil
}

//FormFieldName returns the form field name used for CSRF Protection.
//
//Use to embed together with Value in forms.
//
//It will return an ErrRequestMustHaveContext error if called outside Handler.Handler stacktrace.
func FormFieldName(r *http.Request) (string, *WebError) {
	//Checks for context. If it exists, return.
	c, ok := r.Context().Value(ctxHandler).(*Config)
	if !ok {
		return "", ErrRequestMustHaveContext
	}
	if c.formFieldName == "" {
		return defaultFormFieldName, nil
	}
	return c.formFieldName, nil
}

//Value returns the form field value used for CSRF Protection.
//
//Use to embed together with FormFieldName in forms.
//
//TODO
//It will return an ErrNotFound error if CSRF cookie is not found.
//
//It will return an ErrRequestMustHaveContext error if called outside Handler.Handler stacktrace.
func Value(r *http.Request) (string, *WebError) {
	c, ok := r.Context().Value(ctxHandler).(*Config)
	if !ok {
		return "", ErrRequestMustHaveContext
	}

	name := c.name
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

//Delete send a Cookie with MaxAge 0 in the response, that commands the browser to delete the Cookie.
//
//Use to finish a CSRF Session.
//
//Notice that the JWT token is still valid even after this method is called.
//So a external functionality, like CSRF Token revocation or a linked Session Token revocation is needed to ensure no replay attacks are used.
//
//It will return an ErrRequestMustHaveContext error if called outside Handler.Handler stacktrace.
func Delete(w http.ResponseWriter, r *http.Request) *WebError {
	c, ok := r.Context().Value(ctxHandler).(*Config)
	if !ok {
		return ErrRequestMustHaveContext
	}

	deleteCookie(c, w)
	return nil
}

//Error retrieves the CSRF cookie handling error, when inside Handler.ErrorHandler.
//If called outside an Handler.ErrorHandler it will return nil.
func Error(r *http.Request) *WebError {
	m, ok := r.Context().Value(ctxError).(*WebError)
	if !ok {
		return nil
	}
	return m
}

func checkPrerequisites(c *Config, r *http.Request) *WebError {
	//Only TLS requests are really protected by CSRF token protection. So deny non TLS requests.
	if r.TLS == nil {
		return ErrMustUseTLS
	}

	//Only can serve requests that the cookie domains allowed or it will never receive the CSRF Protextion Cookie. Normally a configuration error.
	if c.domain != "" && r.Host != c.domain[1:] && !strings.HasSuffix(r.Host, c.domain) {
		return ErrDomainMustMatchRequest
	}

	//The same is valid for the cookie path. Only can serve requests that the cookie path allowed it to receive the cookie.
	if c.path != "" && c.path != r.URL.Path && !strings.HasPrefix(strings.TrimRight(r.URL.Path, "/")+"/", strings.TrimRight(c.path, "/")+"/") {
		return ErrPathMustMatchRequest
	}

	//No errors
	return nil
}

//checkOrigin returns a error if a CSRF attack was found in Origin HTTP header.
func checkOrigin(c *Config, r *http.Request) *WebError {
	//Check Origin header only if it is present (because it is not mandatory and Firefox does not send it).
	o := r.Header.Get("Origin")
	if o == "" {
		return nil
	}

	//In any case Origin came from the target is valid.
	//Bonus if o is not a root(/) absolute https URL this will fail.
	if o == "https://"+r.Host {
		return nil
	}

	//Origin != target and  no domain set. Use the strict rules...
	if c.domain == "" {
		return ErrOriginMustMatchRequest
	}

	//Parse the Origin URL (an error is considered a mismatch) and check if it is https.
	oURL, err := url.Parse(o)
	if err != nil || oURL.Scheme != "https" {
		return ErrOriginMustMatchRequest
	}

	//...but if there is a cookie domain set, loosen the rules and allow it to compare with the suffix too.
	//Bonus if o is not a root(/) absolute https URL this will fail too.
	if o != "https://"+c.domain[1:] && !strings.HasSuffix(o, c.domain) {
		return ErrOriginMustMatchRequest
	}

	return nil
}

//checkReferer returns a error if a CSRF attack was found in Referer HTTP header.
func checkReferer(c *Config, r *http.Request) *WebError {
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
		if c.domain == "" {
			return ErrRefererMustMatchRequest
		}
		//If there is a cookie domain set, loosen the rules and allow it to compare with the suffix too.
		if refURL.Host != c.domain[1:] && !strings.HasSuffix(refURL.Host, c.domain) {
			return ErrRefererMustMatchCookieDomain
		}
	}

	//If case there is a cookie path set, stricten the rules based on a path prefix.
	if c.path != "" && c.path != refURL.Path && !strings.HasPrefix(strings.TrimRight(refURL.Path, "/")+"/", strings.TrimRight(c.path, "/")+"/") {
		return ErrRefererMustMatchCookiePath
	}
	return nil
}

//checkOriginAndReferer returns a error if a CSRF attack was found in these Origin and Referer HTTP headers.
func checkOriginAndReferer(c *Config, r *http.Request) *WebError {
	if err := checkOrigin(c, r); err != nil {
		return err
	}
	if err := checkReferer(c, r); err != nil {
		return err
	}

	origin := r.Header.Get("Origin")
	referer := r.Referer()
	if origin != "" && referer != origin && !strings.HasPrefix(strings.TrimRight(referer, "/")+"/", strings.TrimRight(origin, "/")+"/") {
		return ErrOriginAndRefererMustMatch
	}
	return nil
}

func checkTokenValue(c *Config, r *http.Request, requestToken string) *WebError {
	//Retrieve the CSRF token value from cookie checking if it exists.
	name := c.name
	if name == "" {
		name = DefaultName
	}

	//Find the CSRF Cookie assuring it is unique.
	//To avoid nasty bugs on users, delete if it is not unique(That is the reason not use r.Cookie(name)).
	//It can happens when a cookie domain is added or changed.
	var cookie *http.Cookie
	for _, ac := range r.Cookies() {
		if ac.Name == name {
			if cookie != nil {
				return ErrMustBeUnique
			}
			cookie = ac
		}
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

//deleteCookie send various a Cookie with MaxAge 0 in response, that commands the browser to delete the Cookie.
func deleteCookie(c *Config, w http.ResponseWriter) {
	//Retrieve the custom or default cookie name.
	name := c.name
	if name == "" {
		name = DefaultName
	}

	//A cookie with MaxAge=-1 (MaxAge 0 is sent in HTTP) is a command to browser to delete the cookie.
	cookie := &http.Cookie{
		Name:     name,
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		Domain:   c.domain,
		Path:     c.path,
	}

	//Send the cookie in response.
	http.SetCookie(w, cookie)
}

func secret(c *Config, r *http.Request) ([]byte, *WebError) {
	//Retrieve the Token secret (Custom or generated). Handle errors.
	if c.SecretFunc == nil {
		return nil, ErrSecretError
	}
	secret := c.SecretFunc(r)
	//It is part of the contract. Never return an empty secret. (Because it is no secret that way.)
	if secret == nil || len(secret) == 0 {
		return nil, ErrSecretError
	}

	return secret, nil
}

//errorHandler calls the Handler.ErrorHandler it there is one, if not, call the default behavior.
func errorHandler(c *Config, webErr *WebError, w http.ResponseWriter, r *http.Request) {
	//Handle both special case for deletion of cookies.
	if webErr == ErrTokenSignatureMustMatch {
		deleteCookie(c, w)
	}
	if webErr == ErrMustBeUnique {
		name := c.name
		if name == "" {
			name = DefaultName
		}
		cookie.DeepDelete(name, w, r)
	}

	//In case of an custom error handler is defined, call ErrorHandler with a error in the context.
	if c.ErrorHandler != nil {
		c.ErrorHandler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxError, webErr)))
		return

	}

	//No custom error handler, use the default handler.
	http.Error(w, fmt.Sprintf("%d - %s", webErr.HTTPStatusCode, http.StatusText(webErr.HTTPStatusCode)), webErr.HTTPStatusCode)
}
