package csrfcookie_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitlab.com/gopherburrow/csrfcookie"
)

var defConf = &csrfcookie.Config{SecretFunc: defaultSecret, ErrorHandler: http.HandlerFunc(errorHandlerFunc)}

func defaultSecret(r *http.Request) []byte {
	return []byte("secret")
}

func TestNewFormHandler_success_default(t *testing.T) {
	handler, form, cookie := setupFormHandlerAndRequestGETOnCreateCSRF(t, defConf, "https://www.example.com")
	rr := newPostFormRequest(t, handler, "https://www.example.com", cookie, "https://www.example.com", "https://www.example.com/", form)
	if want, got := http.StatusOK, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}

	//Testing without Origin Header
	rr = newPostFormRequest(t, handler, "https://www.example.com", cookie, "", "https://www.example.com", form)
	if want, got := http.StatusOK, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
}

func TestNewFormHandler_success_cookieNameDomainPathAndCSRFHeader(t *testing.T) {
	conf := &csrfcookie.Config{
		SecretFunc: func(r *http.Request) []byte {
			return []byte("secret")
		},
		ErrorHandler: http.HandlerFunc(errorHandlerFunc),
	}
	if err := conf.SetName("example-api-csrf-token"); err != nil {
		t.Fatal(err)
	}
	if err := conf.SetDomain(".example.com"); err != nil {
		t.Fatal(err)
	}
	if err := conf.SetPath("/api"); err != nil {
		t.Fatal(err)
	}
	if err := conf.SetFormFieldName("_xsrf_"); err != nil {
		t.Fatal(err)
	}
	if err := conf.SetHeaderName("X-My-Csrf-Header"); err != nil {
		t.Fatal(err)
	}
	h, err := csrfcookie.NewAPIHandler(conf, http.HandlerFunc(createCSRFValueFunc))
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app1.example.com/api/resource1", nil)
	h.ServeHTTP(rr, req)
	if want, got := http.StatusOK, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	c := cookie(t, rr, "example-api-csrf-token")

	rr = newPostAPIRequest(t, h, "https://app2.example.com/api/resource2", c, "https://app1.example.com", "https://app1.example.com/api/resource1", "X-My-Csrf-Header", rr.Body.String())
	if want, got := http.StatusOK, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}

	//Testing without Origin Header
	rr = newPostAPIRequest(t, h, "https://app2.example.com/api/resource2", c, "", "https://app1.example.com/api", "X-My-Csrf-Header", rr.Body.String())
	if want, got := http.StatusOK, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
}

func TestNewAPIHandler_success_default(t *testing.T) {
	handler, csrfValue, cookie := setupAPIHandlerAndRequestGETOnCreateCSRF(t, defConf, "https://www.example.com")
	rr := newPostAPIRequest(t, handler, "https://www.example.com", cookie, "https://www.example.com", "https://www.example.com/", csrfcookie.DefaultHeaderName, csrfValue)
	if want, got := http.StatusOK, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}

	//Testing without Origin Header
	rr = newPostAPIRequest(t, handler, "https://www.example.com", cookie, "", "https://www.example.com", csrfcookie.DefaultHeaderName, csrfValue)
	if want, got := http.StatusOK, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
}

func TestNewAPIHandler_success_cookieNameDomainAndPath(t *testing.T) {
	conf := &csrfcookie.Config{
		SecretFunc: func(r *http.Request) []byte {
			return []byte("secret")
		},
		ErrorHandler: http.HandlerFunc(errorHandlerFunc),
	}
	if err := conf.SetName("example-api-csrf-token"); err != nil {
		t.Fatal(err)
	}
	if err := conf.SetDomain(".example.com"); err != nil {
		t.Fatal(err)
	}
	if err := conf.SetPath("/api"); err != nil {
		t.Fatal(err)
	}
	if err := conf.SetFormFieldName("_xsrf_"); err != nil {
		t.Fatal(err)
	}
	h, err := csrfcookie.NewFormHandler(conf, http.HandlerFunc(createCSRFFormValueFunc))
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app1.example.com/api/resource1", nil)
	h.ServeHTTP(rr, req)
	if want, got := http.StatusOK, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	c := cookie(t, rr, "example-api-csrf-token")

	rr = newPostFormRequest(t, h, "https://app2.example.com/api/resource2", c, "https://app1.example.com", "https://app1.example.com/api/resource1", rr.Body.String())
	if want, got := http.StatusOK, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}

	//Testing without Origin Header
	rr = newPostFormRequest(t, h, "https://app2.example.com/api/resource2", c, "", "https://app1.example.com/api", rr.Body.String())
	if want, got := http.StatusOK, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
}

func TestValue_success(t *testing.T) {
	conf := &csrfcookie.Config{}
	_, _, cookie := setupFormHandlerAndRequestGETOnCreateCSRF(t, defConf, "https://www.example.com")
	cookieValue := cookie.Value
	h2, err := csrfcookie.NewFormHandler(conf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, err := csrfcookie.Value(r)
		if v != cookieValue {
			t.Fatal()
		}
		if err != nil {
			t.Fatal()
		}
	}))
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://www.example.com", nil)
	req.AddCookie(cookie)
	h2.ServeHTTP(rr, req)
	if want, got := http.StatusOK, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
}

func TestDelete_success(t *testing.T) {
	_, form, cookie := setupFormHandlerAndRequestGETOnCreateCSRF(t, defConf, "https://www.example.com")

	deleteFn := func(w http.ResponseWriter, r *http.Request) {
		err := csrfcookie.Delete(w, r)
		if want, got := (*csrfcookie.WebError)(nil), err; want != got {
			t.Fatalf("want=%q, got=%q", want, got)
		}
	}
	h, err := csrfcookie.NewFormHandler(defConf, http.HandlerFunc(deleteFn))
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "https://www.example.com", strings.NewReader(form))
	req.AddCookie(cookie)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Referer", "https://www.example.com")

	h.ServeHTTP(rr, req)

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
	if want, got := csrfcookie.ErrNameMustBeValid, conf.SetName("mytoken;"); want != got {
		t.Fatalf("want=%q, got=%v", want, got)
	}
	if want, got := csrfcookie.ErrDomainMustBeValid, conf.SetDomain("*.example.com"); want != got {
		t.Fatalf("want=%q, got=%v", want, got)
	}
	if want, got := csrfcookie.ErrPathMustBeValid, conf.SetPath(";api"); want != got {
		t.Fatalf("want=%q, got=%v", want, got)
	}
	if want, got := csrfcookie.ErrFormFieldNameMustBeValid, conf.SetFormFieldName(";xsrf"); want != got {
		t.Fatalf("want=%q, got=%v", want, got)
	}
	if want, got := csrfcookie.ErrHeaderNameMustBeValid, conf.SetHeaderName("My-header"); want != got {
		t.Fatalf("want=%q, got=%v", want, got)
	}
	_, err := csrfcookie.NewFormHandler(nil, http.HandlerFunc(createCSRFFormValueFunc))
	if want, got := csrfcookie.ErrConfigMustBeNonNil, err; want != got {
		t.Fatalf("want=%q, got=%v", want, got)
	}
	_, err = csrfcookie.NewFormHandler(conf, nil)
	if want, got := csrfcookie.ErrChainHandlerMustBeNonNil, err; want != got {
		t.Fatalf("want=%q, got=%v", want, got)
	}
	_, err = csrfcookie.NewAPIHandler(nil, http.HandlerFunc(createCSRFFormValueFunc))
	if want, got := csrfcookie.ErrConfigMustBeNonNil, err; want != got {
		t.Fatalf("want=%q, got=%v", want, got)
	}
	_, err = csrfcookie.NewAPIHandler(conf, nil)
	if want, got := csrfcookie.ErrChainHandlerMustBeNonNil, err; want != got {
		t.Fatalf("want=%q, got=%v", want, got)
	}
}

func TestCreateValueDeleteAndFormFieldName_fail_noContext(t *testing.T) {
	unmanagedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := map[string]interface{}{"nonce": "123456"}
		_, err := csrfcookie.Create(w, r, claims)
		if want, got := csrfcookie.ErrRequestMustHaveContext, err; want != got {
			t.Fatalf("want=%q, got=%q", want, got)
		}
		_, err = csrfcookie.Value(r)
		if want, got := csrfcookie.ErrRequestMustHaveContext, err; want != got {
			t.Fatalf("want=%q, got=%q", want, got)
		}
		_, err = csrfcookie.FormFieldName(r)
		if want, got := csrfcookie.ErrRequestMustHaveContext, err; want != got {
			t.Fatalf("want=%q, got=%q", want, got)
		}
		err = csrfcookie.Error(r)
		if want, got := (*csrfcookie.WebError)(nil), err; want != got {
			t.Fatalf("want=%q, got=%q", want, got)
		}
		err = csrfcookie.Delete(w, r)
		if want, got := csrfcookie.ErrRequestMustHaveContext, err; want != got {
			t.Fatalf("want=%q, got=%q", want, got)
		}
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://www.example.com", nil)
	unmanagedHandler.ServeHTTP(rr, req)
}
func TestNewFormHandler_fail_ErrMustUseTLS(t *testing.T) {
	handler, form, cookie := setupFormHandlerAndRequestGETOnCreateCSRF(t, defConf, "https://www.example.com")
	rr := newPostFormRequest(t, handler, "http://www.example.com", cookie, "", "http://www.example.com/", form)
	if want, got := http.StatusInternalServerError, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrMustUseTLS", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestNewFormHandler_fail_ErrCookieDomainMustMatchRequest(t *testing.T) {
	conf := &csrfcookie.Config{SecretFunc: defaultSecret, ErrorHandler: http.HandlerFunc(errorHandlerFunc)}
	if err := conf.SetDomain(".example.com"); err != nil {
		t.Fatal(err)
	}

	handler, form, cookie := setupFormHandlerAndRequestGETOnCreateCSRF(t, conf, "https://www.example.com")
	rr := newPostFormRequest(t, handler, "https://www.otherexample.com", cookie, "", "https://www.otherexample.com/", form)
	if want, got := http.StatusInternalServerError, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrDomainMustMatchRequest", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestNewFormHandler_fail_ErrPathMustMatchRequest(t *testing.T) {
	conf := &csrfcookie.Config{SecretFunc: defaultSecret, ErrorHandler: http.HandlerFunc(errorHandlerFunc)}
	if err := conf.SetPath("/api"); err != nil {
		t.Fatal(err)
	}

	handler, form, cookie := setupFormHandlerAndRequestGETOnCreateCSRF(t, conf, "https://www.example.com/api")
	rr := newPostFormRequest(t, handler, "https://www.example.com", cookie, "", "https://www.example.com", form)
	if want, got := http.StatusInternalServerError, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrPathMustMatchRequest", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestNewFormHandler_fail_ErrRequestMustBeXWwwFormURLEncoded(t *testing.T) {
	handler, form, cookie := setupFormHandlerAndRequestGETOnCreateCSRF(t, defConf, "https://www.example.com")
	req := httptest.NewRequest(http.MethodPost, "https://www.example.com", strings.NewReader(form))
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if want, got := http.StatusUnsupportedMediaType, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrRequestMustBeXWwwFormURLEncoded", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestNewFormHandler_fail_ErrOriginMustMatchRequest(t *testing.T) {
	handler, form, cookie := setupFormHandlerAndRequestGETOnCreateCSRF(t, defConf, "https://www.example.com")
	rr := newPostFormRequest(t, handler, "https://www.example.com", cookie, "https://app1.example.com", "https://app1.example.com", form)
	if want, got := http.StatusForbidden, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrOriginMustMatchRequest", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestNewFormHandler_fail_ErrOriginMustMatchRequestCookieDomain(t *testing.T) {
	conf := &csrfcookie.Config{SecretFunc: defaultSecret, ErrorHandler: http.HandlerFunc(errorHandlerFunc)}
	if err := conf.SetDomain(".example.com"); err != nil {
		t.Fatal(err)
	}
	handler, form, cookie := setupFormHandlerAndRequestGETOnCreateCSRF(t, conf, "https://www.example.com")
	rr := newPostFormRequest(t, handler, "https://www.example.com", cookie, "https://app1.otherexample.com", "https://app1.otherexample.com", form)
	if want, got := http.StatusForbidden, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrOriginMustMatchRequest", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestNewFormHandler_fail_ErrOriginMustMatchRequestCookie_invalidOriginURL(t *testing.T) {
	conf := &csrfcookie.Config{SecretFunc: defaultSecret, ErrorHandler: http.HandlerFunc(errorHandlerFunc)}
	if err := conf.SetDomain(".example.com"); err != nil {
		t.Fatal(err)
	}
	handler, form, cookie := setupFormHandlerAndRequestGETOnCreateCSRF(t, conf, "https://www.example.com")
	rr := newPostFormRequest(t, handler, "https://www.example.com", cookie, "totalgarbage", "https://www.example.com", form)
	if want, got := http.StatusForbidden, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrOriginMustMatchRequest", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestNewFormHandler_fail_ErrRequestMustHaveReferer(t *testing.T) {
	conf := &csrfcookie.Config{SecretFunc: defaultSecret, ErrorHandler: http.HandlerFunc(errorHandlerFunc)}
	handler, form, cookie := setupFormHandlerAndRequestGETOnCreateCSRF(t, conf, "https://www.example.com")
	rr := newPostFormRequest(t, handler, "https://www.example.com", cookie, "https://www.example.com", "", form)
	if want, got := http.StatusForbidden, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrRequestMustHaveReferer", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestNewFormHandler_fail_ErrRefererMustMatchRequest(t *testing.T) {
	conf := &csrfcookie.Config{SecretFunc: defaultSecret, ErrorHandler: http.HandlerFunc(errorHandlerFunc)}
	handler, form, cookie := setupFormHandlerAndRequestGETOnCreateCSRF(t, conf, "https://www.example.com")
	rr := newPostFormRequest(t, handler, "https://www.example.com", cookie, "https://www.example.com", "https://www.otherexample.com", form)
	if want, got := http.StatusForbidden, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrRefererMustMatchRequest", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestNewFormHandler_fail_ErrRefererMustMatchCookiePath_invalidRefererURL(t *testing.T) {
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

func TestNewFormHandler_fail_ErrRefererMustMatchCookieDomain(t *testing.T) {
	conf := &csrfcookie.Config{SecretFunc: defaultSecret, ErrorHandler: http.HandlerFunc(errorHandlerFunc)}
	if err := conf.SetDomain(".example.com"); err != nil {
		t.Fatal(err)
	}
	handler, form, cookie := setupFormHandlerAndRequestGETOnCreateCSRF(t, conf, "https://www.example.com")
	rr := newPostFormRequest(t, handler, "https://www.example.com", cookie, "https://www.example.com", "https://www.otherexample.com", form)
	if want, got := http.StatusForbidden, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrRefererMustMatchCookieDomain", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestNewFormHandler_fail_ErrRefererMustMatchCookiePath(t *testing.T) {
	conf := &csrfcookie.Config{SecretFunc: defaultSecret, ErrorHandler: http.HandlerFunc(errorHandlerFunc)}
	if err := conf.SetPath("/api"); err != nil {
		t.Fatal(err)
	}
	handler, form, cookie := setupFormHandlerAndRequestGETOnCreateCSRF(t, conf, "https://www.example.com/api")
	rr := newPostFormRequest(t, handler, "https://www.example.com/api", cookie, "https://www.example.com", "https://www.example.com", form)
	if want, got := http.StatusForbidden, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrRefererMustMatchCookiePath", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

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

func TestNewAPIHandler_fail_ErrMustUseTLS(t *testing.T) {
	handler, csrfValue, cookie := setupAPIHandlerAndRequestGETOnCreateCSRF(t, defConf, "https://www.example.com")
	rr := newPostAPIRequest(t, handler, "http://www.example.com", cookie, "", "http://www.example.com/", csrfcookie.DefaultHeaderName, csrfValue)
	if want, got := http.StatusInternalServerError, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrMustUseTLS", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestNewAPIHandler_fail_ErrCookieDomainMustMatchRequest(t *testing.T) {
	conf := &csrfcookie.Config{SecretFunc: defaultSecret, ErrorHandler: http.HandlerFunc(errorHandlerFunc)}
	if err := conf.SetDomain(".example.com"); err != nil {
		t.Fatal(err)
	}

	handler, csrfValue, cookie := setupAPIHandlerAndRequestGETOnCreateCSRF(t, conf, "https://www.example.com")
	rr := newPostAPIRequest(t, handler, "https://www.otherexample.com", cookie, "", "https://www.otherexample.com/", csrfcookie.DefaultHeaderName, csrfValue)
	if want, got := http.StatusInternalServerError, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrDomainMustMatchRequest", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestNewAPIHandler_fail_ErrPathMustMatchRequest(t *testing.T) {
	conf := &csrfcookie.Config{SecretFunc: defaultSecret, ErrorHandler: http.HandlerFunc(errorHandlerFunc)}
	if err := conf.SetPath("/api"); err != nil {
		t.Fatal(err)
	}

	handler, csrfValue, cookie := setupAPIHandlerAndRequestGETOnCreateCSRF(t, conf, "https://www.example.com/api")
	rr := newPostAPIRequest(t, handler, "https://www.example.com", cookie, "", "https://www.example.com", csrfcookie.DefaultHeaderName, csrfValue)
	if want, got := http.StatusInternalServerError, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrPathMustMatchRequest", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestNewAPIHandler_fail_ErrOriginMustMatchRequest(t *testing.T) {
	handler, csrfValue, cookie := setupAPIHandlerAndRequestGETOnCreateCSRF(t, defConf, "https://www.example.com")
	rr := newPostAPIRequest(t, handler, "https://www.example.com", cookie, "https://app1.example.com", "https://app1.example.com", csrfcookie.DefaultHeaderName, csrfValue)
	if want, got := http.StatusForbidden, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrOriginMustMatchRequest", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestNewAPIHandler_fail_ErrOriginMustMatchRequestCookieDomain(t *testing.T) {
	conf := &csrfcookie.Config{SecretFunc: defaultSecret, ErrorHandler: http.HandlerFunc(errorHandlerFunc)}
	if err := conf.SetDomain(".example.com"); err != nil {
		t.Fatal(err)
	}
	handler, csrfValue, cookie := setupAPIHandlerAndRequestGETOnCreateCSRF(t, conf, "https://www.example.com")
	rr := newPostAPIRequest(t, handler, "https://www.example.com", cookie, "https://app1.otherexample.com", "https://app1.otherexample.com", csrfcookie.DefaultHeaderName, csrfValue)
	if want, got := http.StatusForbidden, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrOriginMustMatchRequest", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

func TestNewAPIHandler_fail_ErrOriginMustMatchRequestCookie_invalidOriginURL(t *testing.T) {
	conf := &csrfcookie.Config{SecretFunc: defaultSecret, ErrorHandler: http.HandlerFunc(errorHandlerFunc)}
	if err := conf.SetDomain(".example.com"); err != nil {
		t.Fatal(err)
	}
	handler, csrfValue, cookie := setupAPIHandlerAndRequestGETOnCreateCSRF(t, conf, "https://www.example.com")
	rr := newPostAPIRequest(t, handler, "https://www.example.com", cookie, "totalgarbage", "https://www.example.com", csrfcookie.DefaultHeaderName, csrfValue)
	if want, got := http.StatusForbidden, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	if want, got := "ErrOriginMustMatchRequest", rr.Body.String(); want != got {
		t.Fatalf("want=%q, got=%q", want, got)
	}
}

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

func TestWebError_Error(t *testing.T) {
	errors := []*csrfcookie.WebError{
		csrfcookie.ErrRequestMustHaveContext,
		csrfcookie.ErrMustUseTLS,
		csrfcookie.ErrDomainMustMatchRequest,
		csrfcookie.ErrPathMustMatchRequest,
		csrfcookie.ErrSecretError,
		csrfcookie.ErrOriginMustMatchRequest,
		csrfcookie.ErrRequestMustHaveReferer,
		csrfcookie.ErrRefererMustMatchRequest,
		csrfcookie.ErrRefererMustMatchCookieDomain,
		csrfcookie.ErrRefererMustMatchCookiePath,
		csrfcookie.ErrOriginAndRefererMustMatch,
		csrfcookie.ErrMustBeUnique,
		csrfcookie.ErrNotFound,
		csrfcookie.ErrTokenValuesMustMatch,
		csrfcookie.ErrTokenSignatureMustMatch,
	}

	for _, err := range errors {
		if wantPrefix, got := "csrfcookie: ", err.Error(); !strings.HasPrefix(got, wantPrefix) {
			t.Fatalf("want=%q, got=%q", wantPrefix, got)
		}
	}

}

func createCSRFFormValueFunc(w http.ResponseWriter, r *http.Request) {
	claims := map[string]interface{}{"nonce": "123456"}
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
}

func createCSRFValueFunc(w http.ResponseWriter, r *http.Request) {
	claims := map[string]interface{}{"nonce": "123456"}
	v, webErr := csrfcookie.Create(w, r, claims)
	if webErr != nil {
		w.WriteHeader(webErr.HTTPStatusCode)
		fmt.Fprint(w, getErrorName(webErr))
		return
	}
	fmt.Fprint(w, v)
}

func errorHandlerFunc(w http.ResponseWriter, r *http.Request) {
	webErr := csrfcookie.Error(r)
	if webErr == nil {
		http.Error(w, "500 - Error Not Found", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(webErr.HTTPStatusCode)
	fmt.Fprint(w, getErrorName(webErr))
}

func getErrorName(webErr *csrfcookie.WebError) string {
	switch webErr {
	case csrfcookie.ErrMustUseTLS:
		return "ErrMustUseTLS"
	case csrfcookie.ErrDomainMustMatchRequest:
		return "ErrDomainMustMatchRequest"
	case csrfcookie.ErrPathMustMatchRequest:
		return "ErrPathMustMatchRequest"
	case csrfcookie.ErrClaimsMustBeNotEmpty:
		return "ErrClaimsMustBeNotEmpty"
	case csrfcookie.ErrSecretError:
		return "ErrSecretError"
	case csrfcookie.ErrOriginMustMatchRequest:
		return "ErrOriginMustMatchRequest"
	case csrfcookie.ErrRequestMustHaveReferer:
		return "ErrRequestMustHaveReferer"
	case csrfcookie.ErrRefererMustMatchRequest:
		return "ErrRefererMustMatchRequest"
	case csrfcookie.ErrRefererMustMatchCookieDomain:
		return "ErrRefererMustMatchCookieDomain"
	case csrfcookie.ErrRefererMustMatchCookiePath:
		return "ErrRefererMustMatchCookiePath"
	case csrfcookie.ErrOriginAndRefererMustMatch:
		return "ErrOriginAndRefererMustMatch"
	case csrfcookie.ErrMustBeUnique:
		return "ErrMustBeUnique"
	case csrfcookie.ErrNotFound:
		return "ErrNotFound"
	case csrfcookie.ErrTokenValuesMustMatch:
		return "ErrTokenValuesMustMatch"
	case csrfcookie.ErrTokenSignatureMustMatch:
		return "ErrTokenSignatureMustMatch"
	case csrfcookie.ErrRequestMustBeXWwwFormURLEncoded:
		return "ErrRequestMustBeXWwwFormURLEncoded"
	case csrfcookie.ErrCannotReadFormValues:
		return "ErrCannotReadFormValues"
	default:
		return "Unknown Error"
	}

}

func setupFormHandlerAndRequestGETOnCreateCSRF(t *testing.T, c *csrfcookie.Config, url string) (handler http.Handler, form string, ck *http.Cookie) {
	h, err := csrfcookie.NewFormHandler(c, http.HandlerFunc(createCSRFFormValueFunc))
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, url, nil)
	h.ServeHTTP(rr, req)
	if want, got := http.StatusOK, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	return h, rr.Body.String(), cookie(t, rr, csrfcookie.DefaultName)
}

func newPostFormRequest(t *testing.T, h http.Handler, url string, c *http.Cookie, origin, referer, form string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, url, strings.NewReader(form))
	if c != nil {
		req.AddCookie(c)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Add("Origin", origin)

	}
	if referer != "" {
		req.Header.Add("Referer", referer)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func setupAPIHandlerAndRequestGETOnCreateCSRF(t *testing.T, c *csrfcookie.Config, url string) (handler http.Handler, csrfValue string, ck *http.Cookie) {
	h, err := csrfcookie.NewAPIHandler(c, http.HandlerFunc(createCSRFValueFunc))
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, url, nil)
	h.ServeHTTP(rr, req)
	if want, got := http.StatusOK, rr.Code; want != got {
		t.Fatalf("want=%d, got=%d, body=%q", want, got, rr.Body.String())
	}
	return h, rr.Body.String(), cookie(t, rr, csrfcookie.DefaultName)
}

func newPostAPIRequest(t *testing.T, h http.Handler, url string, c *http.Cookie, origin, referer, headerName, headerValue string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, url, nil)
	if c != nil {
		req.AddCookie(c)
	}
	req.Header.Add(headerName, headerValue)
	if origin != "" {
		req.Header.Add("Origin", origin)

	}
	if referer != "" {
		req.Header.Add("Referer", referer)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
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
