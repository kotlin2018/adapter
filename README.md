# Installation

````shell
go get github.com/kotlin2018/adapter
````
# Usage example

````go
package service

import (
	"github.com/casbin/casbin/v2"
	"github.com/kotlin2018/adapter"
)
func init () {
	opts := &adapter.Adapter{
		DriverName: "mysql",
		LinkInfo: "root:root@tcp(127.0.0.1:3306)/casbin",
		TableName: "casbin_rule",
	}
	a, _ := adapter.NewAdapterFromOptions(opts)
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", a)
}
````

