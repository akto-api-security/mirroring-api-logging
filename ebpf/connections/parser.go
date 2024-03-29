package connections

import (
	"sync"

	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/kafkaUtil"
)

func tryReadFromBD(receiveBuffer []byte, sentBuffer []byte, wg *sync.WaitGroup, seq int) {
	kafkaUtil.ParseAndProduce(receiveBuffer, sentBuffer, "", seq, false, "MIRRORING")
	defer wg.Done()
}
