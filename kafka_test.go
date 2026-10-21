package main

import (
	"testing"
	"time"

	"github.com/segmentio/kafka-go"
)

func withKafkaAuthEnv(t *testing.T, mechanism string, authImplemented bool, username, password string) {
	prevMechanism, prevAuth, prevUser, prevPass := kafkaSaslMechanism, isAuthImplemented, kafkaUsername, kafkaPassword
	kafkaSaslMechanism, isAuthImplemented, kafkaUsername, kafkaPassword = mechanism, authImplemented, username, password
	t.Cleanup(func() {
		kafkaSaslMechanism, isAuthImplemented, kafkaUsername, kafkaPassword = prevMechanism, prevAuth, prevUser, prevPass
	})
}

func TestKafkaWriterUsesMskIam(t *testing.T) {
	withKafkaAuthEnv(t, "AWS_MSK_IAM", false, "", "")

	transport := GetKafkaWriter("b-1.msk:9098", "akto.api.logs", 10, time.Second).Transport.(*kafka.Transport)

	if transport.SASL == nil || transport.SASL.Name() != "AWS_MSK_IAM" {
		t.Fatalf("expected AWS_MSK_IAM SASL mechanism, got %v", transport.SASL)
	}
	// MSK IAM listeners are TLS only and use publicly trusted certificates
	if transport.TLS == nil || transport.TLS.InsecureSkipVerify {
		t.Fatalf("expected verified TLS for MSK IAM, got %+v", transport.TLS)
	}
}

func TestKafkaWriterMskIamIgnoresUsernamePassword(t *testing.T) {
	withKafkaAuthEnv(t, "aws_msk_iam", true, "user", "pass")

	transport := GetKafkaWriter("b-1.msk:9098", "akto.api.logs", 10, time.Second).Transport.(*kafka.Transport)

	if transport.SASL == nil || transport.SASL.Name() != "AWS_MSK_IAM" {
		t.Fatalf("expected AWS_MSK_IAM to take precedence over PLAIN, got %v", transport.SASL)
	}
}

func TestKafkaWriterPlainAuthUnchanged(t *testing.T) {
	withKafkaAuthEnv(t, "", true, "user", "pass")

	transport := GetKafkaWriter("kafka:9092", "akto.api.logs", 10, time.Second).Transport.(*kafka.Transport)

	if transport.SASL == nil || transport.SASL.Name() != "PLAIN" {
		t.Fatalf("expected PLAIN SASL mechanism, got %v", transport.SASL)
	}
	if transport.TLS != nil {
		t.Fatalf("expected no TLS when USE_TLS is unset, got %+v", transport.TLS)
	}
}

func TestKafkaWriterNoAuthUnchanged(t *testing.T) {
	withKafkaAuthEnv(t, "", false, "", "")

	transport := GetKafkaWriter("kafka:9092", "akto.api.logs", 10, time.Second).Transport.(*kafka.Transport)

	if transport.SASL != nil || transport.TLS != nil {
		t.Fatalf("expected no SASL and no TLS, got SASL=%v TLS=%+v", transport.SASL, transport.TLS)
	}
}
