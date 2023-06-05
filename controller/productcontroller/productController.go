package productcontroller

import (
	"net/http"

	"github.com/meinantoyuriawan/go-jwt-auth/helper"
)

func Index(w http.ResponseWriter, r *http.Request) {
	data := []map[string]interface{}{
		{
			"id":           1,
			"product_name": "product1",
			"quantity":     1000,
		},
		{
			"id":           2,
			"product_name": "product2",
			"quantity":     200,
		},
		{
			"id":           3,
			"product_name": "product3",
			"quantity":     300,
		},
	}

	helper.ResponseJSON(w, http.StatusOK, data)
}
