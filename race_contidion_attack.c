
#include <stdio.h>
#include <stdint.h>
#include <pthread.h>

uint32_t account[3] = {0, 0, 0};

void *Trd0(void *acc) {

	uint32_t balance;
	pthread_t self_id;
	self_id = pthread_self();

	uint32_t poc = 0;

	for (poc = 0; poc < 10; poc++) {

		balance = account[0];
		sleep(1);
		account[0] = balance - 5;
		account[(uint32_t)acc] += 5;
		printf("Thread %d, account 0 amount %d account %d amount %d\n\n ", (uint32_t)self_id, account[0], acc, account[(uint32_t)acc]);
	}

	pthread_exit(NULL);
}

int main(void) {

	account[0] = 1000;

	pthread_t thread1, thread2;

	pthread_create(&thread1, NULL, Trd0, (void *)1);
	pthread_create(&thread2, NULL, Trd0, (void *)2);

	pthread_join(thread1, NULL);
	pthread_join(thread2, NULL);

	printf("Press Enter\n");
	getchar();

	return 0;
}
