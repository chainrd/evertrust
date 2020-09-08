package service

import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"io"
	"strings"
)

type (
	RpcFn func(*Req) *Rsp

	API struct {
		Namespace string
		Api       map[string]RpcFn
	}

	Service interface {
		APIs() *API
	}

	Req struct {
		Id     string        `json:"id,omitempty"`
		Method string        `json:"method"`
		Params []interface{} `json:"params,omitempty"`
	}
	RspError struct {
		Code    string `json:"code,omitempty"`
		Message string `json:"message,omitempty"`
	}
	Rsp struct {
		Result interface{} `json:"result,omitempty"`
		Error  *RspError   `json:"error,omitempty"`
		Id     string      `json:"id,omitempty"`
	}
)

func NewRsp(id string, result interface{}, err *RspError) *Rsp {
	rsp := &Rsp{Id: id}
	if err != nil {
		rsp.Error = err
	} else {
		rsp.Result = result
	}
	return rsp
}

func (r *Rsp) WriteTo(rw io.Writer) error {
	fmt.Println("response <- ", string(r.Bytes()))
	_, err := rw.Write(r.Bytes())
	return err
}

func (r *Req) WriteTo(rw io.Writer) error {
	//fmt.Println("request -> ", string(r.Bytes()))
	_, err := rw.Write(r.Bytes())
	return err
}

func (r *Rsp) String() string {
	return string(r.Bytes())
}

func (r *Rsp) FromBytes(data []byte) (*Rsp, error) {
	err := json.Unmarshal(data, r)
	return r, err
}

func (r *Rsp) Bytes() []byte {
	buf, _ := json.Marshal(r)
	return buf
}

func NewReq(m string, p []interface{}) *Req {
	adapt := func(a []interface{}) *Req {
		as := make([]string, 0)
		for _, _a := range a {
			__a, ok := _a.(string)
			if !ok {
				return nil
			}
			as = append(as, __a)
		}
		j := strings.Join(as, " ")
		d := make(map[string]interface{})
		if err := json.Unmarshal([]byte(j), &d); err == nil {
			return &Req{uuid.New().String(), m, []interface{}{d}}
		}
		return nil
	}
	if req := adapt(p); req != nil {
		return req
	}
	return &Req{uuid.New().String(), m, p}
}

func (r *Req) String() string {
	return string(r.Bytes())
}

func (r *Req) FromBytes(data []byte) *Req {
	json.Unmarshal(data, r)
	return r
}

func (r *Req) Bytes() []byte {
	buf, _ := json.Marshal(r)
	return buf
}
