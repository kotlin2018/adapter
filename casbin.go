package adapter

import (
	"errors"
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/util"
	"github.com/gogf/gf/frame/g"
	"github.com/gogf/gf/text/gstr"
)

// 需要映射到数据库casbin_rule表的 orm模型，操作这个model就是操作casbin_rule表
type CasBinRule struct {
	PType string `json:"ptype"`
	V0    string `json:"v0"`
	V1    string `json:"v1"`
	V2    string `json:"v2"`
	V3    string `json:"v3"`
	V4    string `json:"v4"`
	V5    string `json:"v5"`
}

// ReqCasBin 请求参数模型，用于对数据库中policy文件，增、删、改、查。
//
// 策略文件 p = sub, obj, act
type CasBinModel struct {
	ID          uint   `json:"id"`
	PType       string `json:"pType"`    // policy缩写，对应: p
	AuthorityId string `json:"roleName"` // 操作者ID，对应: sub
	Path        string `json:"path"`     // 被操作的资源(即: url路径)，对应: obj
	Method      string `json:"method"`   // 操作的方法，例如: GET、POST，对应: act
	BaseAdapter *Adapter
	ReqPolicies []CasBinInfo
	ModelPath   string `json:"modelPath"` // rbac_model.conf 文件路径
}

// CasBinInfo 请求参数
type CasBinInfo struct {
	Path   string `p:"path" json:"path"`     // 被操作的资源(即: url路径)，对应: obj
	Method string `p:"method" json:"method"` // 操作的方法，例如: GET、POST，对应: act
}

var (
	opts = &Adapter{
		DriverName: g.Cfg().GetString("casbin.adapter.DriverName"),
		LinkInfo:   g.Cfg().GetString("casbin.adapter.LinkInfo"),
		TableName:  g.Cfg().GetString("casbin.adapter.TableName"),
	}
	modelPath = g.Cfg().GetString("casbin.ModelPath")

)


// 持久化到数据库，引入自定义规则
func (c *CasBinModel) CasBin() *casbin.Enforcer {
	a, _ := NewAdapterFromOptions(c.BaseAdapter)
	e, _ := casbin.NewEnforcer(c.ModelPath, a)
	e.AddFunction("ParamsMatch", ParamsMatchFunc)
	_ = e.LoadPolicy()
	return e
}

// ParamsMatchFunc 自定义规则函数
func ParamsMatchFunc(args ...interface{}) (interface{}, error) {
	name1 := args[0].(string)
	name2 := args[1].(string)
	return ParamsMatch(name1, name2), nil
}

// ParamsMatch 自定义规则函数
func ParamsMatch(fullNameKey1,key2 string) interface{} {
	// 剥离路径后再使用casBin的keyMatch2
	key1 := gstr.Split(fullNameKey1, "?")[0]
	return util.KeyMatch2(key1, key2)
}

// AddCasBin 添加权限(添加策略规则)
func (c *CasBinModel) AddCasBin() (*casbin.Enforcer,bool) {
	e := c.CasBin()
	success, _ := e.AddPolicy(c.AuthorityId, c.Path, c.Method)
	return e,success
}

// ClearCasBin 清除匹配的权限
//
// 从当前策略中删除授权规则，可以指定字段过滤器。底层调用了e.RemoveFilteredPolicy()
func (c *CasBinModel) ClearCasBin(v int,p ...string) (*casbin.Enforcer,bool) {
	e := c.CasBin()
	success, _ := e.RemoveFilteredPolicy(v, p...)
	return e,success
}

// UpdateCasBin 更新casBin权限
func (c *CasBinModel) UpdateCasBin() (*casbin.Enforcer,error) {
	c.ClearCasBin(0,c.AuthorityId)
	var rules [][]string
	for _, v := range c.ReqPolicies {
		cm := CasBinModel{
			PType: "p",
			AuthorityId: c.AuthorityId,
			Path: v.Path,
			Method: v.Method,
		}
		rules = append(rules,[]string{cm.AuthorityId,cm.Path,cm.Method})
	}
	e := c.CasBin()
	success,_ := e.AddPolicies(rules)
	if success == false {
		return e,errors.New("存在相同api,添加失败,请联系管理员")
	}
	return e,nil
}


// GetCasBinList 获取权限列表
func (c *CasBinModel) GetCasBinList()(e *casbin.Enforcer,pathMaps []CasBinInfo) {
	e = c.CasBin()
	list := e.GetFilteredPolicy(0, c.AuthorityId)
	for _, v := range list {
		pathMaps = append(pathMaps, CasBinInfo{
			Path:   v[1], // 对应 : p = sub, obj, act 中的 obj
			Method: v[2], // 对应 : p = sub, obj, act 中的 act
		})
	}
	return
}

