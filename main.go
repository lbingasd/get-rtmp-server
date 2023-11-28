package main

import (
	"getRtmp/core"
	"strconv"

	"github.com/gin-gonic/gin"
)

func main() {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	r.GET("/getdevices", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"code":    0,
			"devices": core.GetAllDevs(),
		})
	})
	r.GET("/startlisten", func(c *gin.Context) {
		index_str := c.Query("index")

		index, err := strconv.ParseInt(index_str, 10, 64)
		if err == nil {
			ch := make(chan error)
			go core.StartListen(index, ch)
			err := <-ch
			if err == nil {
				c.JSON(200, gin.H{
					"code": 0,
					"name": index,
				})
			} else {
				c.JSON(200, gin.H{
					"code": -1,
					"err":  err,
				})
			}
		} else {
			c.JSON(200, gin.H{
				"code": -2,
				"err":  err,
			})
		}

	})

	r.GET("/streaminfo", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"stream_url":  core.StreamServiceUrl,
			"stream_code": core.StreamCode,
		})
	})
	r.Run(":8888")
}
