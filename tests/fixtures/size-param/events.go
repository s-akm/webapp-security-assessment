package api

func ListEvents(c *gin.Context) {
	batchSize, _ := strconv.Atoi(c.DefaultQuery("batchSize", "50"))
	if batchSize > 500 {
		batchSize = 500
	}
	c.JSON(200, store.Events(batchSize))
}
