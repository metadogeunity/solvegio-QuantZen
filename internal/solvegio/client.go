package solvegio

import("context";"fmt";"io";"net/http";"net/url";"strings";"time")
type Client struct{baseURL string;apiKey string;http *http.Client}
func New(baseURL,apiKey string,timeout time.Duration)*Client{return &Client{baseURL:strings.TrimRight(baseURL,"/"),apiKey:apiKey,http:&http.Client{Timeout:timeout}}}
func(c *Client)Configured()bool{return c.baseURL!=""&&c.apiKey!=""}
func(c *Client)Do(ctx context.Context,method,p string,body io.Reader)(int,http.Header,[]byte,error){if !c.Configured(){return 200,http.Header{},[]byte("{"mode":"demo","message":"SolveGio is not configured; local simulator response"}"),nil};if !strings.HasPrefix(p,"/v1/"){return 0,nil,nil,fmt.Errorf("path not allowed")};u,err:=url.Parse(c.baseURL+p);if err!=nil{return 0,nil,nil,err};req,err:=http.NewRequestWithContext(ctx,method,u.String(),body);if err!=nil{return 0,nil,nil,err};req.Header.Set("X-API-Key",c.apiKey);req.Header.Set("Accept","application/json");if body!=nil{req.Header.Set("Content-Type","application/json")};resp,err:=c.http.Do(req);if err!=nil{return 0,nil,nil,err};defer resp.Body.Close();b,err:=io.ReadAll(io.LimitReader(resp.Body,4<<20));return resp.StatusCode,resp.Header,b,err}
