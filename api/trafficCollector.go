package api

import (
	"bytes"
	"encoding/json"
	"github.com/akto-api-security/mirroring-api-logging/utils"
	"log"
	"net/http"
)

func SendTrafficDataToAPI(trafficCollector utils.TrafficCollectorCounter, url string, token string) {
	wrappedData := map[string]interface{}{
		"trafficCollectorMetrics": trafficCollector,
	}
	jsonData, err := json.Marshal(wrappedData)

	log.Println(string(jsonData))
	if err != nil {
		log.Printf("Error marshalling data: %v", err)
		return
	}

	fullUrl := url + "/api/updateTrafficCollectorMetrics"

	req, err := http.NewRequest("POST", fullUrl, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Error creating request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("authorization", token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error sending request: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("API call failed with status: %d", resp.StatusCode)
		return
	}

	log.Println("API call successful")
}
