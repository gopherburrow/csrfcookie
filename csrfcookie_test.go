package csrfcookie_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"gitlab.com/gopherburrow/csrfcookie"
)

var defConf = &csrfcookie.Config{SecretFunc: defaultSecretFn}
var defClaims = map[string]interface{}{"nonce": "123456"}

func defaultSecretFn(r *http.Request) []byte {
	return []byte("secret")
}

func TestValidate_success_default(t *testing.T) {
	token, cookie, _ := csrfcookie.Create(defConf, nil, defClaims)
	formBody := url.QueryEscape(csrfcookie.DefaultFormFieldName) + "=" + url.QueryEscape(token)
	req := httptest.NewRequest(http.MethodPost, "https://www.example.com", strings.NewReader(formBody))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Origin", "https://www.example.com")
	req.Header.Add("Referer", "https://www.example.com")
	req.Header.Add(csrfcookie.DefaultHeaderName, token)
	req.AddCookie(cookie)
	err := csrfcookie.ValidateWithForm(defConf, req)
	if want, got := error(nil), err; want != got {
		t.Fatalf("want=nil, got=%q", got)
	}

	err = csrfcookie.ValidateWithHeader(defConf, req)
	if want, got := error(nil), err; want != got {
		t.Fatalf("want=nil, got=%q", got)
	}

	//Testing without Origin Header
	req = httptest.NewRequest(http.MethodPost, "https://www.example.com", strings.NewReader(formBody))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Referer", "https://www.example.com")
	req.Header.Add(csrfcookie.DefaultHeaderName, token)
	req.AddCookie(cookie)
	err = csrfcookie.ValidateWithForm(defConf, req)
	if want, got := error(nil), err; want != got {
		t.Fatalf("want=nil, got=%q", got)
	}

	err = csrfcookie.ValidateWithHeader(defConf, req)
	if want, got := error(nil), err; want != got {
		t.Fatalf("want=nil, got=%q", got)
	}
}

func TestValidate_success_ignoreErrTokenValuesMustMatchInGetRequest(t *testing.T) {
	token, cookie, _ := csrfcookie.Create(defConf, nil, defClaims)
	formBody := url.QueryEscape(csrfcookie.DefaultFormFieldName) + "=" + url.QueryEscape(token+"!!!")
	req := httptest.NewRequest(http.MethodGet, "https://www.example.com", strings.NewReader(formBody))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Origin", "https://www.example.com")
	req.Header.Add("Referer", "https://www.example.com")
	req.Header.Add(csrfcookie.DefaultHeaderName, token+"!!!")
	req.AddCookie(cookie)
	err := csrfcookie.ValidateWithForm(defConf, req)
	if want, got := error(nil), err; want != got {
		t.Fatalf("want=nil, got=%q", got)
	}

	err = csrfcookie.ValidateWithHeader(defConf, req)
	if want, got := error(nil), err; want != got {
		t.Fatalf("want=nil, got=%q", got)
	}
}

func TestValidate_success_cookieNameDomainPathAndCSRFHeader(t *testing.T) {
	customConf := &csrfcookie.Config{
		SecretFunc: func(r *http.Request) []byte {
			return []byte("secret")
		},
	}
	if err := customConf.SetCookieName("example-api-csrf-token"); err != nil {
		t.Fatal(err)
	}
	if err := customConf.SetCookieDomain(".example.com"); err != nil {
		t.Fatal(err)
	}
	if err := customConf.SetCookiePath("/api"); err != nil {
		t.Fatal(err)
	}
	const customFormFieldName = "_xsrf_"
	if err := customConf.SetFormFieldName("_xsrf_"); err != nil {
		t.Fatal(err)
	}
	const customHeaderName = "X-My-Csrf-Header"
	if err := customConf.SetHeaderName(customHeaderName); err != nil {
		t.Fatal(err)
	}

	token, cookie, _ := csrfcookie.Create(customConf, nil, defClaims)
	formBody := url.QueryEscape(customFormFieldName) + "=" + url.QueryEscape(token)

	req := httptest.NewRequest(http.MethodPost, "https://app1.example.com/api/resource1", strings.NewReader(formBody))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Origin", "https://app1.example.com")
	req.Header.Add("Referer", "https://app1.example.com/api/resource1")
	req.Header.Add(customHeaderName, token)
	req.AddCookie(cookie)
	err := csrfcookie.ValidateWithForm(customConf, req)
	if want, got := error(nil), err; want != got {
		t.Fatalf("want=nil, got=%q", got)
	}

	err = csrfcookie.ValidateWithHeader(customConf, req)
	if want, got := error(nil), err; want != got {
		t.Fatalf("want=nil, got=%q", got)
	}

}
func TestValue_success(t *testing.T) {
	token, cookie, err := csrfcookie.Create(defConf, nil, defClaims)

	req := httptest.NewRequest(http.MethodGet, "https://www.example.com", nil)
	req.AddCookie(cookie)
	v, err := csrfcookie.Value(defConf, req)
	if want, got := error(nil), err; want != got {
		t.Fatalf("want=nil, got=%q", got)
	}
	if want, got := token, v; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestDelete_success(t *testing.T) {
	rr := httptest.NewRecorder()
	deleteCookie := csrfcookie.DeleteCookie(defConf)
	http.SetCookie(rr, deleteCookie)
	chkCookies := readSetCookies(rr.Header())
	cookieDeletionCount := 0
	for _, chkCookie := range chkCookies {
		if chkCookie.Name != csrfcookie.DefaultName {
			continue
		}
		if want, got := "< 0", chkCookie.MaxAge; got >= 0 {
			t.Fatalf("want=%q, got=%d", want, got)
		}
		cookieDeletionCount++
	}
	if want, got := 1, cookieDeletionCount; want != got {
		t.Fatalf("want=%d, got=%d", want, got)
	}
}

func TestMethods_fail_invalidInputs(t *testing.T) {
	conf := &csrfcookie.Config{}
	if want, got := csrfcookie.ErrNameMustBeValid, conf.SetCookieName("mytoken;"); want != got {
		t.Fatalf("want=%q, got=%v", want, got)
	}
	if want, got := csrfcookie.ErrDomainMustBeValid, conf.SetCookieDomain("*.example.com"); want != got {
		t.Fatalf("want=%q, got=%v", want, got)
	}
	if want, got := csrfcookie.ErrPathMustBeValid, conf.SetCookiePath(";api"); want != got {
		t.Fatalf("want=%q, got=%v", want, got)
	}
	if want, got := csrfcookie.ErrFormFieldNameMustBeValid, conf.SetFormFieldName(";xsrf"); want != got {
		t.Fatalf("want=%q, got=%v", want, got)
	}
	if want, got := csrfcookie.ErrHeaderNameMustBeValid, conf.SetHeaderName("My-header"); want != got {
		t.Fatalf("want=%q, got=%v", want, got)
	}
}

func TestValidate_fail_ErrMustUseTLS(t *testing.T) {
	token, cookie, _ := csrfcookie.Create(defConf, nil, defClaims)
	formBody := url.QueryEscape(csrfcookie.DefaultFormFieldName) + "=" + url.QueryEscape(token)
	req := httptest.NewRequest(http.MethodPost, "http://www.example.com", strings.NewReader(formBody))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Origin", "http://www.example.com")
	req.Header.Add("Referer", "http://www.example.com")
	req.Header.Add(csrfcookie.DefaultHeaderName, token)
	req.AddCookie(cookie)
	err := csrfcookie.ValidateWithForm(defConf, req)
	if want, got := csrfcookie.ErrMustUseTLS, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
	err = csrfcookie.ValidateWithHeader(defConf, req)
	if want, got := csrfcookie.ErrMustUseTLS, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}

}

func TestValidate_fail_ErrCookieDomainMustMatchRequest(t *testing.T) {
	conf := &csrfcookie.Config{SecretFunc: defaultSecretFn}
	if err := conf.SetCookieDomain(".example.com"); err != nil {
		t.Fatal(err)
	}

	token, cookie, _ := csrfcookie.Create(defConf, nil, defClaims)
	formBody := url.QueryEscape(csrfcookie.DefaultFormFieldName) + "=" + url.QueryEscape(token)
	req := httptest.NewRequest(http.MethodPost, "https://www.otherexample.com", strings.NewReader(formBody))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Referer", "https://www.otherexample.com/")
	req.Header.Add(csrfcookie.DefaultHeaderName, token)
	req.AddCookie(cookie)
	err := csrfcookie.ValidateWithForm(conf, req)
	if want, got := csrfcookie.ErrDomainMustMatchRequest, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
	err = csrfcookie.ValidateWithHeader(conf, req)
	if want, got := csrfcookie.ErrDomainMustMatchRequest, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestValidate_fail_ErrPathMustMatchRequest(t *testing.T) {
	conf := &csrfcookie.Config{SecretFunc: defaultSecretFn}
	if err := conf.SetCookiePath("/api"); err != nil {
		t.Fatal(err)
	}

	token, cookie, _ := csrfcookie.Create(defConf, nil, defClaims)
	formBody := url.QueryEscape(csrfcookie.DefaultFormFieldName) + "=" + url.QueryEscape(token)
	req := httptest.NewRequest(http.MethodPost, "https://www.example.com", strings.NewReader(formBody))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Referer", "https://www.example.com")
	req.Header.Add(csrfcookie.DefaultHeaderName, token)
	req.AddCookie(cookie)
	err := csrfcookie.ValidateWithForm(conf, req)
	if want, got := csrfcookie.ErrPathMustMatchRequest, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
	err = csrfcookie.ValidateWithHeader(conf, req)
	if want, got := csrfcookie.ErrPathMustMatchRequest, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestValidate_fail_ErrRequestMustBeXWwwFormURLEncoded(t *testing.T) {
	token, cookie, _ := csrfcookie.Create(defConf, nil, defClaims)
	formBody := url.QueryEscape(csrfcookie.DefaultFormFieldName) + "=" + url.QueryEscape(token)
	req := httptest.NewRequest(http.MethodPost, "https://www.example.com", strings.NewReader(formBody))
	req.Header.Add("Origin", "https://www.example.com")
	req.Header.Add("Referer", "https://www.example.com")
	req.AddCookie(cookie)
	err := csrfcookie.ValidateWithForm(defConf, req)
	if want, got := csrfcookie.ErrRequestMustBeXWwwFormURLEncoded, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestValidate_fail_ErrOriginMustMatchRequest(t *testing.T) {
	token, cookie, _ := csrfcookie.Create(defConf, nil, defClaims)
	formBody := url.QueryEscape(csrfcookie.DefaultFormFieldName) + "=" + url.QueryEscape(token)
	req := httptest.NewRequest(http.MethodPost, "https://www.example.com", strings.NewReader(formBody))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Origin", "https://app1.example.com")
	req.Header.Add("Referer", "https://app1.example.com")
	req.Header.Add(csrfcookie.DefaultHeaderName, token)
	req.AddCookie(cookie)
	err := csrfcookie.ValidateWithForm(defConf, req)
	if want, got := csrfcookie.ErrOriginMustMatchRequest, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
	err = csrfcookie.ValidateWithHeader(defConf, req)
	if want, got := csrfcookie.ErrOriginMustMatchRequest, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestValidate_fail_ErrOriginMustMatchRequestCookieDomain(t *testing.T) {
	conf := &csrfcookie.Config{SecretFunc: defaultSecretFn}
	if err := conf.SetCookieDomain(".example.com"); err != nil {
		t.Fatal(err)
	}
	token, cookie, _ := csrfcookie.Create(defConf, nil, defClaims)
	formBody := url.QueryEscape(csrfcookie.DefaultFormFieldName) + "=" + url.QueryEscape(token)
	req := httptest.NewRequest(http.MethodPost, "https://www.example.com", strings.NewReader(formBody))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Origin", "https://app1.otherexample.com")
	req.Header.Add("Referer", "https://app1.otherexample.com")
	req.Header.Add(csrfcookie.DefaultHeaderName, token)
	req.AddCookie(cookie)
	err := csrfcookie.ValidateWithForm(conf, req)
	if want, got := csrfcookie.ErrOriginMustMatchRequest, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
	err = csrfcookie.ValidateWithHeader(conf, req)
	if want, got := csrfcookie.ErrOriginMustMatchRequest, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestValidate_fail_ErrOriginMustMatchRequestCookie_invalidOriginURL(t *testing.T) {
	conf := &csrfcookie.Config{SecretFunc: defaultSecretFn}
	if err := conf.SetCookieDomain(".example.com"); err != nil {
		t.Fatal(err)
	}
	token, cookie, _ := csrfcookie.Create(conf, nil, defClaims)
	formBody := url.QueryEscape(csrfcookie.DefaultFormFieldName) + "=" + url.QueryEscape(token)
	req := httptest.NewRequest(http.MethodPost, "https://www.example.com", strings.NewReader(formBody))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Origin", "invalid")
	req.Header.Add("Referer", "https://www.example.com")
	req.Header.Add(csrfcookie.DefaultHeaderName, token)
	req.AddCookie(cookie)
	err := csrfcookie.ValidateWithForm(conf, req)
	if want, got := csrfcookie.ErrOriginMustMatchRequest, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
	err = csrfcookie.ValidateWithHeader(conf, req)
	if want, got := csrfcookie.ErrOriginMustMatchRequest, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestValidate_fail_ErrRequestMustHaveReferer(t *testing.T) {
	token, cookie, _ := csrfcookie.Create(defConf, nil, defClaims)
	formBody := url.QueryEscape(csrfcookie.DefaultFormFieldName) + "=" + url.QueryEscape(token)
	req := httptest.NewRequest(http.MethodPost, "https://www.example.com", strings.NewReader(formBody))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Origin", "https://www.example.com")
	req.Header.Add(csrfcookie.DefaultHeaderName, token)
	req.AddCookie(cookie)
	err := csrfcookie.ValidateWithForm(defConf, req)
	if want, got := csrfcookie.ErrRequestMustHaveReferer, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
	err = csrfcookie.ValidateWithHeader(defConf, req)
	if want, got := csrfcookie.ErrRequestMustHaveReferer, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestValidate_fail_ErrRefererMustMatchRequest(t *testing.T) {
	token, cookie, _ := csrfcookie.Create(defConf, nil, defClaims)
	formBody := url.QueryEscape(csrfcookie.DefaultFormFieldName) + "=" + url.QueryEscape(token)
	req := httptest.NewRequest(http.MethodPost, "https://www.example.com", strings.NewReader(formBody))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Origin", "https://www.example.com")
	req.Header.Add("Referer", "https://www.otherexample.com")
	req.Header.Add(csrfcookie.DefaultHeaderName, token)
	req.AddCookie(cookie)
	err := csrfcookie.ValidateWithForm(defConf, req)
	if want, got := csrfcookie.ErrRefererMustMatchRequest, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
	err = csrfcookie.ValidateWithHeader(defConf, req)
	if want, got := csrfcookie.ErrRefererMustMatchRequest, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestValidate_fail_ErrRefererMustMatchCookiePath_invalidRefererURL(t *testing.T) {
	token, cookie, _ := csrfcookie.Create(defConf, nil, defClaims)
	formBody := url.QueryEscape(csrfcookie.DefaultFormFieldName) + "=" + url.QueryEscape(token)
	req := httptest.NewRequest(http.MethodPost, "https://www.example.com", strings.NewReader(formBody))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Origin", "https://www.example.com")
	req.Header.Add("Referer", "totalgarbage")
	req.Header.Add(csrfcookie.DefaultHeaderName, token)
	req.AddCookie(cookie)
	err := csrfcookie.ValidateWithForm(defConf, req)
	if want, got := csrfcookie.ErrRefererMustMatchRequest, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
	err = csrfcookie.ValidateWithHeader(defConf, req)
	if want, got := csrfcookie.ErrRefererMustMatchRequest, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestValidate_fail_ErrRefererMustMatchCookieDomain(t *testing.T) {
	conf := &csrfcookie.Config{SecretFunc: defaultSecretFn}
	if err := conf.SetCookieDomain(".example.com"); err != nil {
		t.Fatal(err)
	}

	token, cookie, _ := csrfcookie.Create(conf, nil, defClaims)
	formBody := url.QueryEscape(csrfcookie.DefaultFormFieldName) + "=" + url.QueryEscape(token)
	req := httptest.NewRequest(http.MethodPost, "https://www.example.com", strings.NewReader(formBody))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Origin", "https://www.example.com")
	req.Header.Add("Referer", "https://www.otherexample.com")
	req.Header.Add(csrfcookie.DefaultHeaderName, token)
	req.AddCookie(cookie)
	err := csrfcookie.ValidateWithForm(conf, req)
	if want, got := csrfcookie.ErrRefererMustMatchCookieDomain, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}

	err = csrfcookie.ValidateWithHeader(conf, req)
	if want, got := csrfcookie.ErrRefererMustMatchCookieDomain, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}

}

func TestValidate_fail_ErrRefererMustMatchCookiePath(t *testing.T) {
	conf := &csrfcookie.Config{SecretFunc: defaultSecretFn}
	if err := conf.SetCookiePath("/api"); err != nil {
		t.Fatal(err)
	}

	token, cookie, _ := csrfcookie.Create(conf, nil, defClaims)
	formBody := url.QueryEscape(csrfcookie.DefaultFormFieldName) + "=" + url.QueryEscape(token)
	req := httptest.NewRequest(http.MethodPost, "https://www.example.com/api", strings.NewReader(formBody))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Origin", "https://www.example.com")
	req.Header.Add("Referer", "https://www.example.com")
	req.Header.Add(csrfcookie.DefaultHeaderName, token)
	req.AddCookie(cookie)
	err := csrfcookie.ValidateWithForm(conf, req)
	if want, got := csrfcookie.ErrRefererMustMatchCookiePath, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}

	err = csrfcookie.ValidateWithHeader(conf, req)
	if want, got := csrfcookie.ErrRefererMustMatchCookiePath, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestValidate_fail_ErrRefererMustMatchOrigin(t *testing.T) {
	conf := &csrfcookie.Config{SecretFunc: defaultSecretFn}
	if err := conf.SetCookieDomain(".example.com"); err != nil {
		t.Fatal(err)
	}

	token, cookie, _ := csrfcookie.Create(conf, nil, defClaims)
	formBody := url.QueryEscape(csrfcookie.DefaultFormFieldName) + "=" + url.QueryEscape(token)
	req := httptest.NewRequest(http.MethodPost, "https://www.example.com", strings.NewReader(formBody))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Origin", "https://app1.example.com")
	req.Header.Add("Referer", "https://app2.example.com")
	req.Header.Add(csrfcookie.DefaultHeaderName, token)
	req.AddCookie(cookie)
	err := csrfcookie.ValidateWithForm(conf, req)
	if want, got := csrfcookie.ErrOriginAndRefererMustMatch, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}

	err = csrfcookie.ValidateWithHeader(conf, req)
	if want, got := csrfcookie.ErrOriginAndRefererMustMatch, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestValidate_fail_ErrCannotReadFormValues(t *testing.T) {
	token, cookie, _ := csrfcookie.Create(defConf, nil, defClaims)
	req := httptest.NewRequest(http.MethodPost, "https://www.example.com", strings.NewReader("@%=sfsdfsdf5"))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Origin", "https://www.example.com")
	req.Header.Add("Referer", "https://www.example.com")
	req.Header.Add(csrfcookie.DefaultHeaderName, token)
	req.AddCookie(cookie)
	err := csrfcookie.ValidateWithForm(defConf, req)
	if want, got := csrfcookie.ErrCannotReadFormValues, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}

	err = csrfcookie.ValidateWithHeader(defConf, req)
	if want, got := error(nil), err; want != got {
		t.Fatalf("want=nil, got=%q", got)
	}
}

func TestValidate_fail_ErrMustBeUnique(t *testing.T) {
	token, cookie, _ := csrfcookie.Create(defConf, nil, defClaims)
	formBody := url.QueryEscape(csrfcookie.DefaultFormFieldName) + "=" + url.QueryEscape(token)
	req := httptest.NewRequest(http.MethodPost, "https://www.example.com", strings.NewReader(formBody))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Origin", "https://www.example.com")
	req.Header.Add("Referer", "https://www.example.com")
	req.Header.Add(csrfcookie.DefaultHeaderName, token)
	//Non related Cookie
	req.AddCookie(&http.Cookie{
		Name:  "Spurious-Cookie",
		Value: "Spurious Value",
	})
	//Double Add the same cookie.
	req.AddCookie(cookie)
	req.AddCookie(cookie)
	err := csrfcookie.ValidateWithForm(defConf, req)
	if want, got := csrfcookie.ErrMustBeUnique, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}

	err = csrfcookie.ValidateWithHeader(defConf, req)
	if want, got := csrfcookie.ErrMustBeUnique, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestValidate_fail_ErrNotFound(t *testing.T) {
	token, _, _ := csrfcookie.Create(defConf, nil, defClaims)
	formBody := url.QueryEscape(csrfcookie.DefaultFormFieldName) + "=" + url.QueryEscape(token)
	req := httptest.NewRequest(http.MethodPost, "https://www.example.com", strings.NewReader(formBody))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Origin", "https://www.example.com")
	req.Header.Add("Referer", "https://www.example.com")

	err := csrfcookie.ValidateWithForm(defConf, req)
	if want, got := csrfcookie.ErrNotFound, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}

	err = csrfcookie.ValidateWithHeader(defConf, req)
	if want, got := csrfcookie.ErrNotFound, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}

}

func TestValue_fail_ErrNotFound(t *testing.T) {
	token, _, _ := csrfcookie.Create(defConf, nil, defClaims)
	formBody := url.QueryEscape(csrfcookie.DefaultFormFieldName) + "=" + url.QueryEscape(token)
	req := httptest.NewRequest(http.MethodPost, "https://www.example.com", strings.NewReader(formBody))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Origin", "https://www.example.com")
	req.Header.Add("Referer", "https://www.example.com")

	value, err := csrfcookie.Value(defConf, req)
	if wantValue, gotValue, wantErr, gotErr := "", value, csrfcookie.ErrNotFound, err; wantValue != gotValue || wantErr != gotErr {
		t.Fatalf("wantValue=%q, gotValue=%q, wantErr=%q, getErr=%q", wantValue, gotValue, wantErr, gotErr)
	}
}

func TestValidate_fail_ErrTokenValuesMustMatch(t *testing.T) {
	token, cookie, _ := csrfcookie.Create(defConf, nil, defClaims)
	formBody := url.QueryEscape(csrfcookie.DefaultFormFieldName) + "=" + url.QueryEscape(token+"!!!")
	req := httptest.NewRequest(http.MethodPost, "https://www.example.com", strings.NewReader(formBody))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Origin", "https://www.example.com")
	req.Header.Add("Referer", "https://www.example.com")
	req.Header.Add(csrfcookie.DefaultHeaderName, token+"!!!")
	req.AddCookie(cookie)
	err := csrfcookie.ValidateWithForm(defConf, req)
	if want, got := csrfcookie.ErrTokenValuesMustMatch, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}

	err = csrfcookie.ValidateWithHeader(defConf, req)
	if want, got := csrfcookie.ErrTokenValuesMustMatch, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestValidate_fail_ErrSecretError(t *testing.T) {
	nilSecretFn := func(r *http.Request) []byte {
		return nil
	}

	emptySecretFn := func(r *http.Request) []byte {
		return []byte{}
	}

	conf := &csrfcookie.Config{SecretFunc: defaultSecretFn}
	token, cookie, err := csrfcookie.Create(conf, nil, defClaims)
	if want, got := error(nil), err; want != got {
		t.Fatalf("want=nil, got=%q", got)
	}
	formBody := url.QueryEscape(csrfcookie.DefaultFormFieldName) + "=" + url.QueryEscape(token)
	req := httptest.NewRequest(http.MethodPost, "https://www.example.com", strings.NewReader(formBody))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Origin", "https://www.example.com")
	req.Header.Add("Referer", "https://www.example.com")
	req.Header.Add(csrfcookie.DefaultHeaderName, token)
	req.AddCookie(cookie)

	conf.SecretFunc = nil
	err = csrfcookie.ValidateWithForm(conf, req)
	if want, got := csrfcookie.ErrSecretError, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
	err = csrfcookie.ValidateWithHeader(conf, req)
	if want, got := csrfcookie.ErrSecretError, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}

	conf.SecretFunc = nilSecretFn
	err = csrfcookie.ValidateWithForm(conf, req)
	if want, got := csrfcookie.ErrSecretError, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
	err = csrfcookie.ValidateWithHeader(conf, req)
	if want, got := csrfcookie.ErrSecretError, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}

	conf.SecretFunc = emptySecretFn
	err = csrfcookie.ValidateWithForm(conf, req)
	if want, got := csrfcookie.ErrSecretError, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
	err = csrfcookie.ValidateWithHeader(conf, req)
	if want, got := csrfcookie.ErrSecretError, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestValidate_fail_ErrTokenSignatureMustMatch(t *testing.T) {

	conf := &csrfcookie.Config{SecretFunc: defaultSecretFn}

	token, cookie, err := csrfcookie.Create(conf, nil, defClaims)
	if want, got := error(nil), err; want != got {
		t.Fatalf("want=nil, got=%q", got)
	}

	conf.SecretFunc = func(r *http.Request) []byte {
		return []byte("othersecret")
	}
	formBody := url.QueryEscape(csrfcookie.DefaultFormFieldName) + "=" + url.QueryEscape(token)
	req := httptest.NewRequest(http.MethodPost, "https://www.example.com", strings.NewReader(formBody))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Origin", "https://www.example.com")
	req.Header.Add("Referer", "https://www.example.com")
	req.Header.Add(csrfcookie.DefaultHeaderName, token)
	req.AddCookie(cookie)
	err = csrfcookie.ValidateWithForm(conf, req)
	if want, got := csrfcookie.ErrTokenSignatureMustMatch, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}

	err = csrfcookie.ValidateWithHeader(conf, req)
	if want, got := csrfcookie.ErrTokenSignatureMustMatch, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestCreate_fail_ErrClaimsMustBeNotEmpty(t *testing.T) {
	token, cookie, err := csrfcookie.Create(defConf, nil, nil)
	if want, got := token, ""; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
	if want, got := (*http.Cookie)(nil), cookie; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
	if want, got := csrfcookie.ErrClaimsMustBeNotEmpty, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}

	emptyClaims := map[string]interface{}{}

	token, cookie, err = csrfcookie.Create(defConf, nil, emptyClaims)
	if want, got := token, ""; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
	if want, got := (*http.Cookie)(nil), cookie; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
	if want, got := csrfcookie.ErrClaimsMustBeNotEmpty, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestCreate_fail_ErrSecretError(t *testing.T) {
	nilSecretFn := func(r *http.Request) []byte {
		return nil
	}

	emptySecretFn := func(r *http.Request) []byte {
		return []byte{}
	}

	conf := &csrfcookie.Config{SecretFunc: nilSecretFn}
	token, cookie, err := csrfcookie.Create(conf, nil, defClaims)
	if want, got := token, ""; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
	if want, got := (*http.Cookie)(nil), cookie; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
	if want, got := csrfcookie.ErrSecretError, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}

	conf.SecretFunc = emptySecretFn
	token, cookie, err = csrfcookie.Create(conf, nil, defClaims)
	if want, got := token, ""; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
	if want, got := (*http.Cookie)(nil), cookie; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
	if want, got := csrfcookie.ErrSecretError, err; want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}
