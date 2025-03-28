// Copyright 2021 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package collector

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/prometheus/common/promslog"
)

func TestRemoteInfoStats(t *testing.T) {
	// Testcases created using:
	//  docker run -d -p 9200:9200 elasticsearch:VERSION-alpine
	//  curl http://localhost:9200/_cluster/settings/?include_defaults=true
	files := []string{"../fixtures/settings-5.4.2.json", "../fixtures/settings-merge-5.4.2.json"}
	for _, filename := range files {
		f, _ := os.Open(filename)
		defer f.Close()
		for hn, handler := range map[string]http.Handler{
			"plain": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.Copy(w, f)
			}),
		} {
			ts := httptest.NewServer(handler)
			defer ts.Close()

			u, err := url.Parse(ts.URL)
			if err != nil {
				t.Fatalf("Failed to parse URL: %s", err)
			}
			c := NewRemoteInfo(promslog.NewNopLogger(), http.DefaultClient, u)
			nsr, err := c.fetchAndDecodeRemoteInfoStats()
			if err != nil {
				t.Fatalf("Failed to fetch or decode remote info stats: %s", err)
			}
			t.Logf("[%s/%s] Remote Info Stats Response: %+v", hn, filename, nsr)

		}
	}
}
