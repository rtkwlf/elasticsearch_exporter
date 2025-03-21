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
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"path"

	"github.com/prometheus/client_golang/prometheus"
)

// Labels for remote info metrics
var defaulRemoteInfoLabels = []string{"remote_cluster"}
var defaultRemoteInfoLabelValues = func(remote_cluster string) []string {
	return []string{
		remote_cluster,
	}
}

type remoteInfoMetric struct {
	Type   prometheus.ValueType
	Desc   *prometheus.Desc
	Value  func(remoteStats RemoteCluster) float64
	Labels func(remote_cluster string) []string
}

// RemoteInfo information struct
type RemoteInfo struct {
	logger *slog.Logger
	client *http.Client
	url    *url.URL

	up                              prometheus.Gauge
	totalScrapes, jsonParseFailures prometheus.Counter

	remoteInfoMetrics []*remoteInfoMetric
}

// NewClusterSettings defines Cluster Settings Prometheus metrics
func NewRemoteInfo(logger *slog.Logger, client *http.Client, url *url.URL) *RemoteInfo {

	return &RemoteInfo{
		logger: logger,
		client: client,
		url:    url,

		up: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: prometheus.BuildFQName(namespace, "remote_info_stats", "up"),
			Help: "Was the last scrape of the ElasticSearch remote info endpoint successful.",
		}),
		totalScrapes: prometheus.NewCounter(prometheus.CounterOpts{
			Name: prometheus.BuildFQName(namespace, "remote_info_stats", "total_scrapes"),
			Help: "Current total ElasticSearch remote info scrapes.",
		}),
		jsonParseFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: prometheus.BuildFQName(namespace, "remote_info_stats", "json_parse_failures"),
			Help: "Number of errors while parsing JSON.",
		}),
		// Send all of the remote metrics
		remoteInfoMetrics: []*remoteInfoMetric{
			{
				Type: prometheus.GaugeValue,
				Desc: prometheus.NewDesc(
					prometheus.BuildFQName(namespace, "remote_info", "num_nodes_connected"),
					"Number of nodes connected", defaulRemoteInfoLabels, nil,
				),
				Value: func(remoteStats RemoteCluster) float64 {
					return float64(remoteStats.NumNodesConnected)
				},
				Labels: defaultRemoteInfoLabelValues,
			},
			{
				Type: prometheus.GaugeValue,
				Desc: prometheus.NewDesc(
					prometheus.BuildFQName(namespace, "remote_info", "num_proxy_sockets_connected"),
					"Number of proxy sockets connected", defaulRemoteInfoLabels, nil,
				),
				Value: func(remoteStats RemoteCluster) float64 {
					return float64(remoteStats.NumProxySocketsConnected)
				},
				Labels: defaultRemoteInfoLabelValues,
			},
			{
				Type: prometheus.GaugeValue,
				Desc: prometheus.NewDesc(
					prometheus.BuildFQName(namespace, "remote_info", "max_connections_per_cluster"),
					"Max connections per cluster", defaulRemoteInfoLabels, nil,
				),
				Value: func(remoteStats RemoteCluster) float64 {
					return float64(remoteStats.MaxConnectionsPerCluster)
				},
				Labels: defaultRemoteInfoLabelValues,
			},
		},
	}
}

func (c *RemoteInfo) fetchAndDecodeRemoteInfoStats() (RemoteInfoResponse, error) {
	var rir RemoteInfoResponse

	u := *c.url
	u.Path = path.Join(u.Path, "/_remote/info")

	res, err := c.client.Get(u.String())
	if err != nil {
		return rir, fmt.Errorf("failed to get remote info from %s://%s:%s%s: %s",
			u.Scheme, u.Hostname(), u.Port(), u.Path, err)
	}

	defer func() {
		err = res.Body.Close()
		if err != nil {
			c.logger.Warn(
				"failed to close http.Client",
				"err", err,
			)
		}
	}()

	if res.StatusCode != http.StatusOK {
		return rir, fmt.Errorf("HTTP Request failed with code %d", res.StatusCode)
	}

	if err := json.NewDecoder(res.Body).Decode(&rir); err != nil {
		c.jsonParseFailures.Inc()
		return rir, err
	}
	return rir, nil
}

// Collect gets remote info values
func (ri *RemoteInfo) Collect(ch chan<- prometheus.Metric) {
	ri.totalScrapes.Inc()
	defer func() {
		ch <- ri.up
		ch <- ri.totalScrapes
		ch <- ri.jsonParseFailures
	}()

	remoteInfoResp, err := ri.fetchAndDecodeRemoteInfoStats()
	if err != nil {
		ri.up.Set(0)
		ri.logger.Warn(
			"failed to fetch and decode remote info",
			"err", err,
		)
		return
	}
	ri.totalScrapes.Inc()
	ri.up.Set(1)

	// Remote Info
	for remote_cluster, remoteInfo := range remoteInfoResp {
		for _, metric := range ri.remoteInfoMetrics {
			ch <- prometheus.MustNewConstMetric(
				metric.Desc,
				metric.Type,
				metric.Value(remoteInfo),
				metric.Labels(remote_cluster)...,
			)
		}
	}
}

// Describe add Indices metrics descriptions
func (ri *RemoteInfo) Describe(ch chan<- *prometheus.Desc) {
	for _, metric := range ri.remoteInfoMetrics {
		ch <- metric.Desc
	}
	ch <- ri.up.Desc()
	ch <- ri.totalScrapes.Desc()
	ch <- ri.jsonParseFailures.Desc()
}
