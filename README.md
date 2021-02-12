# Installation

````shell
go get github.com/kotlin2018/adapter
````
# Usage example

````go
package mian

import (
	"github.com/casbin/casbin/v2"
	"github.com/gogf/gf/frame/g"
	"github.com/kotlin2018/adapter"
)

func main() {
	opts := &adapter.Adapter{
		DriverName: "mysql",
		LinkInfo:   "root:root@tcp(127.0.0.1:3306)/casbin",
		TableName:  "casbin_rule",
	}

	c := &adapter.CasBinModel{
		BaseAdapter: opts,
		ModelPath:   "examples/rbac_model.conf",
	}
	// 添加权限
	c.AuthorityId = "100"
	c.Path = "v1/user"
	c.Method = "POST"
	c.AddCasBin()
	
	// 清除匹配的权限
	c.ClearCasBin()
	
	// 更新casBin权限
	c.AuthorityId = "101"
	c.ReqPolicies = []adapter.CasBinInfo{}
	c.UpdateCasBin()
	
	// 获取权限列表
	c.GetCasBinList()
	
}
````


