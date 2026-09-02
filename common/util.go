package common

import (
	"github.com/sirupsen/logrus"
	"os"
)

func GetValFromEnVar(envVar string) (val string) {
	val, ok := os.LookupEnv(envVar)
	if !ok {
		logrus.Debugf("%s not set", envVar)
		return ""
	} else {
		logrus.Debugf("%s is configured", envVar)
		return val
	}
}
