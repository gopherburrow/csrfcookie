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
	csrfcookie.Delete(defConf, rr)
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

func TestNewFormHandler_fail_ErrRequestMustHaveReferer(t *testing.T) {
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

func TestNewFormHandler_fail_ErrRefererMustMatchRequest(t *testing.T) {
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

/*func TestValidate_fail_ErrRefererMustMatchCookiePath_invalidRefererURL(t *testing.T) {
	conf := &csrfcookie.Config{SecretFunc: defaultSecret, ErrorHandler: http.HandlerFunc(errorHandlerFunc)}
	if err := conf.SetPath("/api"); err != nil {
		t.Fatal(err)
	}
	handler, form, cookie := setupFormHandlerAndRequestGETOnCreateCSRF(t, conf, "https://www.example.com/api")
	rr := newPostFormRequest(t, handler, "https://www.example.com/api", cookie, "https://www.example.com", "totalgarbage", form)
	if want, got := http.StatusForbidden, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrRefererMustMatchRequest", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}
*/

func TestNewFormHandler_fail_ErrRefererMustMatchCookieDomain(t *testing.T) {
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

func TestNewFormHandler_fail_ErrRefererMustMatchCookiePath(t *testing.T) {
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

/*
func TestNewFormHandler_fail_ErrRefererMustMatchOrigin(t *testing.T) {
	conf := &csrfcookie.Config{SecretFunc: defaultSecret, ErrorHandler: http.HandlerFunc(errorHandlerFunc)}
	if err := conf.SetDomain(".example.com"); err != nil {
		t.Fatal(err)
	}
	handler, form, cookie := setupFormHandlerAndRequestGETOnCreateCSRF(t, conf, "https://www.example.com")
	rr := newPostFormRequest(t, handler, "https://www.example.com", cookie, "https://app1.example.com", "https://app2.example.com", form)
	if want, got := http.StatusForbidden, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrOriginAndRefererMustMatch", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestNewFormHandler_fail_ErrCannotReadFormValues(t *testing.T) {
	handler, _, cookie := setupFormHandlerAndRequestGETOnCreateCSRF(t, defConf, "https://www.example.com")
	rr := newPostFormRequest(t, handler, "https://www.example.com", cookie, "", "https://www.example.com", "@%=sfsdfsdf5")
	if want, got := http.StatusBadRequest, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrCannotReadFormValues", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestNewFormHandler_fail_ErrMustBeUnique(t *testing.T) {
	handler, form, cookie := setupFormHandlerAndRequestGETOnCreateCSRF(t, defConf, "https://www.example.com/path1/subpath")
	req := httptest.NewRequest(http.MethodPost, "https://www.example.com/path1/subpath", strings.NewReader(form))
	req.AddCookie(&http.Cookie{
		Name:  "Spurious-Cookie",
		Value: "Spurious Value",
	})
	req.AddCookie(cookie)
	cookie2 := &http.Cookie{
		Name:  csrfcookie.DefaultName,
		Value: "123456789011234546789091234567890",
	}
	req.AddCookie(cookie2)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Referer", "https://www.example.com")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if want, got := http.StatusForbidden, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrMustBeUnique", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
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
	if want, got := 12, cookieDeletionCount; want != got {
		t.Fatalf("want=%d, got=%d", want, got)
	}
}

func TestNewFormHandler_fail_ErrNotFound(t *testing.T) {
	handler, form, _ := setupFormHandlerAndRequestGETOnCreateCSRF(t, defConf, "https://www.example.com")
	rr := newPostFormRequest(t, handler, "https://www.example.com", nil, "", "https://www.example.com", form)
	if want, got := http.StatusForbidden, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrNotFound", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestNewFormHandler_fail_ErrTokenValuesMustMatch(t *testing.T) {
	handler, _, cookie := setupFormHandlerAndRequestGETOnCreateCSRF(t, defConf, "https://www.example.com")
	rr := newPostFormRequest(t, handler, "https://www.example.com", cookie, "", "https://www.example.com", "")
	if want, got := http.StatusForbidden, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrTokenValuesMustMatch", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestNewFormHandler_fail_ErrSecretError(t *testing.T) {
	conf := &csrfcookie.Config{SecretFunc: defaultSecret, ErrorHandler: http.HandlerFunc(errorHandlerFunc)}
	handler, form, cookie := setupFormHandlerAndRequestGETOnCreateCSRF(t, conf, "https://www.example.com")
	conf.SecretFunc = nil
	rr := newPostFormRequest(t, handler, "https://www.example.com", cookie, "", "https://www.example.com", form)
	if want, got := http.StatusInternalServerError, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrSecretError", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
	conf.SecretFunc = func(r *http.Request) []byte {
		return nil
	}
	rr = newPostFormRequest(t, handler, "https://www.example.com", cookie, "", "https://www.example.com", form)
	if want, got := http.StatusInternalServerError, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrSecretError", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
	conf.SecretFunc = func(r *http.Request) []byte {
		return []byte{}
	}
	rr = newPostFormRequest(t, handler, "https://www.example.com", cookie, "", "https://www.example.com", form)
	if want, got := http.StatusInternalServerError, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrSecretError", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestNewFormHandler_fail_ErrTokenSignatureMustMatch(t *testing.T) {
	conf := &csrfcookie.Config{SecretFunc: defaultSecret, ErrorHandler: http.HandlerFunc(errorHandlerFunc)}
	handler, form, cookie := setupFormHandlerAndRequestGETOnCreateCSRF(t, conf, "https://www.example.com")
	conf.SecretFunc = func(r *http.Request) []byte {
		return []byte("othersecret")
	}
	rr := newPostFormRequest(t, handler, "https://www.example.com", cookie, "", "https://www.example.com", form)
	if want, got := http.StatusForbidden, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrTokenSignatureMustMatch", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

//******************

func TestNewAPIHandler_fail_ErrRequestMustHaveReferer(t *testing.T) {
	conf := &csrfcookie.Config{SecretFunc: defaultSecret, ErrorHandler: http.HandlerFunc(errorHandlerFunc)}
	handler, csrfValue, cookie := setupAPIHandlerAndRequestGETOnCreateCSRF(t, conf, "https://www.example.com")
	rr := newPostAPIRequest(t, handler, "https://www.example.com", cookie, "https://www.example.com", "", csrfcookie.DefaultHeaderName, csrfValue)
	if want, got := http.StatusForbidden, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrRequestMustHaveReferer", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestNewAPIHandler_fail_ErrRefererMustMatchRequest(t *testing.T) {
	conf := &csrfcookie.Config{SecretFunc: defaultSecret, ErrorHandler: http.HandlerFunc(errorHandlerFunc)}
	handler, csrfValue, cookie := setupAPIHandlerAndRequestGETOnCreateCSRF(t, conf, "https://www.example.com")
	rr := newPostAPIRequest(t, handler, "https://www.example.com", cookie, "https://www.example.com", "https://www.otherexample.com", csrfcookie.DefaultHeaderName, csrfValue)
	if want, got := http.StatusForbidden, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrRefererMustMatchRequest", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestNewAPIHandler_fail_ErrRefererMustMatchCookiePath_invalidRefererURL(t *testing.T) {
	conf := &csrfcookie.Config{SecretFunc: defaultSecret, ErrorHandler: http.HandlerFunc(errorHandlerFunc)}
	if err := conf.SetPath("/api"); err != nil {
		t.Fatal(err)
	}
	handler, csrfValue, cookie := setupAPIHandlerAndRequestGETOnCreateCSRF(t, conf, "https://www.example.com/api")
	rr := newPostAPIRequest(t, handler, "https://www.example.com/api", cookie, "https://www.example.com", "totalgarbage", csrfcookie.DefaultHeaderName, csrfValue)
	if want, got := http.StatusForbidden, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrRefererMustMatchRequest", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestNewAPIHandler_fail_ErrRefererMustMatchCookieDomain(t *testing.T) {
	conf := &csrfcookie.Config{SecretFunc: defaultSecret, ErrorHandler: http.HandlerFunc(errorHandlerFunc)}
	if err := conf.SetDomain(".example.com"); err != nil {
		t.Fatal(err)
	}
	handler, csrfValue, cookie := setupAPIHandlerAndRequestGETOnCreateCSRF(t, conf, "https://www.example.com")
	rr := newPostAPIRequest(t, handler, "https://www.example.com", cookie, "https://www.example.com", "https://www.otherexample.com", csrfcookie.DefaultHeaderName, csrfValue)
	if want, got := http.StatusForbidden, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrRefererMustMatchCookieDomain", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestNewAPIHandler_fail_ErrRefererMustMatchCookiePath(t *testing.T) {
	conf := &csrfcookie.Config{SecretFunc: defaultSecret, ErrorHandler: http.HandlerFunc(errorHandlerFunc)}
	if err := conf.SetPath("/api"); err != nil {
		t.Fatal(err)
	}
	handler, csrfValue, cookie := setupAPIHandlerAndRequestGETOnCreateCSRF(t, conf, "https://www.example.com/api")
	rr := newPostAPIRequest(t, handler, "https://www.example.com/api", cookie, "https://www.example.com", "https://www.example.com", csrfcookie.DefaultHeaderName, csrfValue)
	if want, got := http.StatusForbidden, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrRefererMustMatchCookiePath", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestNewAPIHandler_fail_ErrRefererMustMatchOrigin(t *testing.T) {
	conf := &csrfcookie.Config{SecretFunc: defaultSecret, ErrorHandler: http.HandlerFunc(errorHandlerFunc)}
	if err := conf.SetDomain(".example.com"); err != nil {
		t.Fatal(err)
	}
	handler, csrfValue, cookie := setupAPIHandlerAndRequestGETOnCreateCSRF(t, conf, "https://www.example.com")
	rr := newPostAPIRequest(t, handler, "https://www.example.com", cookie, "https://app1.example.com", "https://app2.example.com", csrfcookie.DefaultHeaderName, csrfValue)
	if want, got := http.StatusForbidden, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrOriginAndRefererMustMatch", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestNewAPIHandler_fail_ErrMustBeUnique(t *testing.T) {
	handler, csrfValue, cookie := setupAPIHandlerAndRequestGETOnCreateCSRF(t, defConf, "https://www.example.com/path1/subpath")
	req := httptest.NewRequest(http.MethodPost, "https://www.example.com/path1/subpath", strings.NewReader(csrfValue))
	req.AddCookie(cookie)
	cookie2 := &http.Cookie{
		Name:  csrfcookie.DefaultName,
		Value: "123456789011234546789091234567890",
	}
	req.AddCookie(cookie2)
	req.Header.Add("Content-Type", "application/x-www-csrfValue-urlencoded")
	req.Header.Add("Referer", "https://www.example.com")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if want, got := http.StatusForbidden, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrMustBeUnique", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
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
	if want, got := 12, cookieDeletionCount; want != got {
		t.Fatalf("want=%d, got=%d", want, got)
	}
}

func TestNewAPIHandler_fail_ErrNotFound(t *testing.T) {
	handler, csrfValue, _ := setupAPIHandlerAndRequestGETOnCreateCSRF(t, defConf, "https://www.example.com")
	rr := newPostAPIRequest(t, handler, "https://www.example.com", nil, "", "https://www.example.com", csrfcookie.DefaultHeaderName, csrfValue)
	if want, got := http.StatusForbidden, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrNotFound", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestNewAPIHandler_fail_ErrTokenValuesMustMatch(t *testing.T) {
	handler, _, cookie := setupAPIHandlerAndRequestGETOnCreateCSRF(t, defConf, "https://www.example.com")
	rr := newPostAPIRequest(t, handler, "https://www.example.com", cookie, "", "https://www.example.com", csrfcookie.DefaultHeaderName, "")
	if want, got := http.StatusForbidden, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrTokenValuesMustMatch", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestNewAPIHandler_fail_ErrSecretError(t *testing.T) {
	conf := &csrfcookie.Config{SecretFunc: defaultSecret, ErrorHandler: http.HandlerFunc(errorHandlerFunc)}
	handler, csrfValue, cookie := setupAPIHandlerAndRequestGETOnCreateCSRF(t, conf, "https://www.example.com")
	conf.SecretFunc = nil
	rr := newPostAPIRequest(t, handler, "https://www.example.com", cookie, "", "https://www.example.com", csrfcookie.DefaultHeaderName, csrfValue)
	if want, got := http.StatusInternalServerError, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrSecretError", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
	conf.SecretFunc = func(r *http.Request) []byte {
		return nil
	}
	rr = newPostAPIRequest(t, handler, "https://www.example.com", cookie, "", "https://www.example.com", csrfcookie.DefaultHeaderName, csrfValue)
	if want, got := http.StatusInternalServerError, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrSecretError", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
	conf.SecretFunc = func(r *http.Request) []byte {
		return []byte{}
	}
	rr = newPostAPIRequest(t, handler, "https://www.example.com", cookie, "", "https://www.example.com", csrfcookie.DefaultHeaderName, csrfValue)
	if want, got := http.StatusInternalServerError, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrSecretError", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestNewAPIHandler_fail_ErrTokenSignatureMustMatch(t *testing.T) {
	conf := &csrfcookie.Config{SecretFunc: defaultSecret, ErrorHandler: http.HandlerFunc(errorHandlerFunc)}
	handler, csrfValue, cookie := setupAPIHandlerAndRequestGETOnCreateCSRF(t, conf, "https://www.example.com")
	conf.SecretFunc = func(r *http.Request) []byte {
		return []byte("othersecret")
	}
	rr := newPostAPIRequest(t, handler, "https://www.example.com", cookie, "", "https://www.example.com", csrfcookie.DefaultHeaderName, csrfValue)
	if want, got := http.StatusForbidden, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrTokenSignatureMustMatch", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

//*******************

func TestCreate_fail_ErrClaimsMustBeNotEmpty_NilClaim(t *testing.T) {
	conf := &csrfcookie.Config{ErrorHandler: http.HandlerFunc(errorHandlerFunc)}
	h, err := csrfcookie.NewFormHandler(conf, http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			v, webErr := csrfcookie.Create(w, r, nil)
			if webErr != nil {
				w.WriteHeader(webErr.HTTPStatusCode)
				fmt.Fprint(w, getErrorName(webErr))
				return
			}
			k, webErr := csrfcookie.FormFieldName(r)
			if webErr != nil {
				w.WriteHeader(webErr.HTTPStatusCode)
				fmt.Fprint(w, getErrorName(webErr))
				return
			}
			fmt.Fprint(w, k+"="+v)
		},
	))
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://www.example.com", nil)
	h.ServeHTTP(rr, req)
	if want, got := http.StatusInternalServerError, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrClaimsMustBeNotEmpty", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
	conf.SecretFunc = func(r *http.Request) []byte {
		return nil
	}
}

func TestCreate_fail_ErrClaimsMustBeNotEmpty_EmptyClaim(t *testing.T) {
	conf := &csrfcookie.Config{ErrorHandler: http.HandlerFunc(errorHandlerFunc)}
	h, err := csrfcookie.NewFormHandler(conf, http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			claims := map[string]interface{}{}
			v, webErr := csrfcookie.Create(w, r, claims)
			if webErr != nil {
				w.WriteHeader(webErr.HTTPStatusCode)
				fmt.Fprint(w, getErrorName(webErr))
				return
			}
			k, webErr := csrfcookie.FormFieldName(r)
			if webErr != nil {
				w.WriteHeader(webErr.HTTPStatusCode)
				fmt.Fprint(w, getErrorName(webErr))
				return
			}
			fmt.Fprint(w, k+"="+v)
		},
	))
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://www.example.com", nil)
	h.ServeHTTP(rr, req)
	if want, got := http.StatusInternalServerError, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrClaimsMustBeNotEmpty", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
	conf.SecretFunc = func(r *http.Request) []byte {
		return nil
	}
}

func TestCreate_fail_ErrSecretError(t *testing.T) {
	conf := &csrfcookie.Config{ErrorHandler: http.HandlerFunc(errorHandlerFunc)}
	h, err := csrfcookie.NewFormHandler(conf, http.HandlerFunc(createCSRFFormValueFunc))
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://www.example.com", nil)
	h.ServeHTTP(rr, req)
	if want, got := http.StatusInternalServerError, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrSecretError", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
	conf.SecretFunc = func(r *http.Request) []byte {
		return nil
	}
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "https://www.example.com", nil)
	h.ServeHTTP(rr, req)
	if want, got := http.StatusInternalServerError, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrSecretError", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
	conf.SecretFunc = func(r *http.Request) []byte {
		return []byte{}
	}
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "https://www.example.com", nil)
	h.ServeHTTP(rr, req)
	if want, got := http.StatusInternalServerError, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrSecretError", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestValue_fail_ErrNotFound(t *testing.T) {
	valueFn := func(w http.ResponseWriter, r *http.Request) {
		value, webErr := csrfcookie.Value(r)
		if wantValue, wantErr, gotValue, gotErr := "", csrfcookie.ErrNotFound, value, webErr; wantValue != gotValue || wantErr != gotErr {
			t.Fatalf("wantValue=%q, gotValue=%q, wantErr=%q, gotErr=%q", wantValue, gotValue, wantErr, gotErr)
		}
	}
	h, err := csrfcookie.NewFormHandler(defConf, http.HandlerFunc(valueFn))
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://www.example.com", nil)
	h.ServeHTTP(rr, req)
}

func TestNewAPIHandler_fail_ErrTokenValuesMustMatch_NoDefaultHandler(t *testing.T) {
	conf := &csrfcookie.Config{SecretFunc: defaultSecret}

	handler, _, cookie := setupAPIHandlerAndRequestGETOnCreateCSRF(t, conf, "https://www.example.com")
	rr := newPostAPIRequest(t, handler, "https://www.example.com", cookie, "", "https://www.example.com", csrfcookie.DefaultHeaderName, "")
	if want, got := http.StatusForbidden, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "403 - Forbidden\n", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func cookie(t *testing.T, rr *httptest.ResponseRecorder, cookieName string) (c *http.Cookie) {
	for _, v := range readSetCookies(rr.HeaderMap) {
		if v.Name == cookieName {
			if c != nil {
				t.Fatal("duplicated cookie")
			}
			c = v
		}
	}
	if c == nil {
		return nil
	}
	if want, got := true, c.HttpOnly; want != got {
		t.Fatalf("want=%t, got=%t", want, got)
	}
	if want, got := true, c.Secure; want != got {
		t.Fatalf("want=%t, got=%t", want, got)
	}
	return c
}
*/
