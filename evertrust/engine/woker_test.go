package engine

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestRealIP(t *testing.T) {
	var wg sync.WaitGroup

	for i := 1; i < 10000; i++ {
		wg.Add(1)
		go func(ii int) {
			defer wg.Done()

			ip := RealIP()
			//t.Logf("goroutine[%d]:%s", ii, ip.String())
			fmt.Printf("goroutine[%d]:%s \n", ii, ip.String())
			time.Sleep(time.Second * 20)
		}(i)
	}

	wg.Wait()
}
