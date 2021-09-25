package main

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

var passwords = [3]string{
	"My favorite password",
	"jumpcloud",
	"1Forg0t",
}

func testPasswordHash(index int, t *testing.T) {
	expectedIdentifier := index + 1
	formData := url.Values{}
	formData.Set("password", passwords[index])

	encodedFormData := formData.Encode()
	params := strings.NewReader(encodedFormData)

	fmt.Printf("Running hash resquest test # %d\n", index)

	req := httptest.NewRequest(http.MethodPost, HashRequestRoute, params)

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(encodedFormData)))

	w := httptest.NewRecorder()

	server(w, req)
	res := w.Result()

	defer res.Body.Close()
	data, err := ioutil.ReadAll(res.Body)

	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	expectedResult := HashRequestIdentifier{Id: expectedIdentifier}
	var actualResult HashRequestIdentifier

	err = json.Unmarshal(data, &actualResult)
	if err != nil {
		t.Errorf("expected unmarshal error to be nil got %v", err)
	}

	if expectedResult.Id != actualResult.Id {
		t.Errorf("expected id=%d, but got id=%d", expectedResult.Id, actualResult.Id)
	}
}

func testGetHash(index int, t *testing.T) {
	expectedIdentifier := index + 1
	respReq := httptest.NewRequest(http.MethodGet, fmt.Sprintf("%s/%d", HashRequestRoute, expectedIdentifier), nil)
	respW := httptest.NewRecorder()

	server(respW, respReq)
	respRes := respW.Result()
	defer respRes.Body.Close()

	if respW.Code == 202 {
		fmt.Println("Reponse is 202, waiting...")
		time.Sleep(6 * time.Second)

		respW = httptest.NewRecorder()
		server(respW, respReq)
		respRes = respW.Result()
	}

	respData, respErr := ioutil.ReadAll(respW.Body)
	if respErr != nil {
		t.Errorf("Results: expected error to be nil got %v", respErr)
	}

	actualHash := string(respData)
	fmt.Printf("test hash is %s\n", actualHash)

	hasher := sha512.New()
	hasher.Write([]byte(passwords[index]))
	expectedHashValue := base64.URLEncoding.EncodeToString(hasher.Sum(nil))

	if actualHash != expectedHashValue {
		t.Errorf("expected hash=%s, but got %s", expectedHashValue, actualHash)
	}
}

func testStats(t *testing.T) {
	// Test the stats
	respReq := httptest.NewRequest(http.MethodGet, StatsRoute, nil)
	respW := httptest.NewRecorder()

	server(respW, respReq)
	respRes := respW.Result()
	defer respRes.Body.Close()

	respData, respErr := ioutil.ReadAll(respW.Body)
	if respErr != nil {
		t.Errorf("Results: expected error to be nil got %v", respErr)
	}

	var actualResult HashStats

	err := json.Unmarshal(respData, &actualResult)
	if err != nil {
		t.Errorf("expected unmarshal error to be nil got %v", err)
	}

	if actualResult.Total != int64(len(passwords)) {
		t.Errorf("Stats: expected number to be %d got %d", len(passwords), actualResult.Total)
	}
}

func TestHashRequest(t *testing.T) {

	for i := 0; i < len(passwords); i++ {
		testPasswordHash(i, t)

		// Get the result
		testGetHash(i, t)
	}

	testStats(t)
}
