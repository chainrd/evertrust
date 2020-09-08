package frequency

import (
	"fmt"
	"testing"
	"time"
)

func TestPeriodFreqControl(t *testing.T) {
	//key := []byte("abc")
	key := "abc"
	key1 := "abc1"
	key2 := "abc2"
	InitFlush()
	PeriodFreqControl(key1, 2 * time.Second, 10)
	PeriodFreqControl(key2, 5 * time.Second, 10)

	for {
		time.Sleep(1 * time.Second)
		err := PeriodFreqControl(key, 3 * time.Second, 30)
		if err != nil {
			t.Error("!!!!!!!!!!!", err)
			break
		}
	}

	t.Log("end-------------")
}

func TestFrequencyControl(t *testing.T) {
	InitFlush()

	FrequencyControl("abc1", 2 * time.Second)
	FrequencyControl("abc2", 4 * time.Second)

	for {
		err := FrequencyControl("abc", 1 * time.Second)
		if err != nil {
			t.Error("!!!!!!!!!!!!!", err)
			break
		}
		fmt.Println("aaaaaaaaaaa")
		time.Sleep(1 * time.Second)
	}
}