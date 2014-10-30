// Copyright 2014 The oauth2 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build appenginevm !appengine

package google

import (
	"bytes"
	"encoding/gob"
	"log"
	"testing"
	"time"

	"code.google.com/p/goprotobuf/proto"
	"github.com/golang/oauth2"
	"google.golang.org/appengine/internal"
	pb "google.golang.org/appengine/internal/memcache"
)

const testScope = "myscope"

type fakeContext struct {
	callsMade        []string
	expiresInSeconds int32
}

func (c *fakeContext) Debugf(format string, args ...interface{})    {}
func (c *fakeContext) Infof(format string, args ...interface{})     {}
func (c *fakeContext) Warningf(format string, args ...interface{})  {}
func (c *fakeContext) Errorf(format string, args ...interface{})    {}
func (c *fakeContext) Criticalf(format string, args ...interface{}) {}
func (c *fakeContext) Call(service, method string, in, out proto.Message, opts *internal.CallOptions) error {
	c.callsMade = append(c.callsMade, service+"."+method)
	if service == "memcache" && method == "Get" {
		res, ok := out.(*pb.MemcacheGetResponse)
		if !ok {
			log.Printf("testing error casting out to pb.MemcacheGetResponse: %#v", out)
		}
		var b bytes.Buffer
		enc := gob.NewEncoder(&b)
		tok := &oauth2.Token{
			Expiry: time.Now().Add(time.Duration(c.expiresInSeconds) * time.Second),
		}
		if err := enc.Encode(*tok); err != nil {
			log.Printf("testing error encoding token: %v", err)
		}
		res.Item = []*pb.MemcacheGetResponse_Item{
			&pb.MemcacheGetResponse_Item{
				Key:              []byte(testScope),
				Value:            b.Bytes(),
				ExpiresInSeconds: proto.Int32(c.expiresInSeconds),
			},
		}
	}
	return nil
}
func (c *fakeContext) FullyQualifiedAppID() string { return "" }
func (c *fakeContext) Request() interface{}        { return nil }

func TestFetchTokenLocalCacheMiss(t *testing.T) {
	ctx := &fakeContext{}
	delete(tokens, testScope) // clear local cache
	config := NewAppEngineConfig(ctx, testScope)
	_, err := config.FetchToken(nil)
	if err != nil {
		t.Errorf("unable to FetchToken: %v", err)
	}
	if w := 3; len(ctx.callsMade) != w {
		t.Errorf("unexpected API calls made: got %v, want %v", len(ctx.callsMade), w)
	}
	w := []string{
		"memcache.Get",
		"app_identity_service.GetAccessToken",
		"memcache.Set",
	}
	for i := range ctx.callsMade {
		if ctx.callsMade[i] != w[i] {
			t.Errorf("unexpected API #%v call made: got %v, want %v", i, ctx.callsMade[i], w[i])
		}
	}
	// Make sure local cache has been populated
	_, ok := tokens[testScope]
	if !ok {
		t.Errorf("local cache not populated!")
	}
}

func TestFetchTokenLocalCacheHit(t *testing.T) {
	ctx := &fakeContext{}
	// Pre-populate the local cache
	tokens[testScope] = &oauth2.Token{
		Expiry: time.Now().Add(1 * time.Hour),
	}
	config := NewAppEngineConfig(ctx, testScope)
	_, err := config.FetchToken(nil)
	if err != nil {
		t.Errorf("unable to FetchToken: %v", err)
	}
	if w := 0; len(ctx.callsMade) != w {
		t.Errorf("unexpected API calls made: got %v, want %v", len(ctx.callsMade), w)
	}
	// Make sure local cache remains populated
	_, ok := tokens[testScope]
	if !ok {
		t.Errorf("local cache not populated!")
	}
}

func TestFetchTokenMemcacheHit(t *testing.T) {
	ctx := &fakeContext{expiresInSeconds: 3600}
	delete(tokens, testScope) // clear local cache
	config := NewAppEngineConfig(ctx, testScope)
	_, err := config.FetchToken(nil)
	if err != nil {
		t.Errorf("unable to FetchToken: %v", err)
	}
	if w := 1; len(ctx.callsMade) != w {
		t.Errorf("unexpected API calls made: got %v, want %v", len(ctx.callsMade), w)
	}
	w := []string{
		"memcache.Get",
	}
	for i := range w {
		if ctx.callsMade[i] != w[i] {
			t.Errorf("unexpected API #%v call made: got %v, want %v", i, ctx.callsMade[i], w[i])
		}
	}
	// Make sure local cache has been populated
	_, ok := tokens[testScope]
	if !ok {
		t.Errorf("local cache not populated!")
	}
}
