package connections

import (
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/kafkaUtil"
)

func tryReadFromBD(receiveBuffer []byte, sentBuffer []byte) {
	kafkaUtil.ParseAndProduce(receiveBuffer, sentBuffer, "", 0, false, "MIRRORING")
}
