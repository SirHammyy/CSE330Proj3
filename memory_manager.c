#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/hrtimer.h>
#include <linux/sched/mm.h>
#include <linux/ktime.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("David Hamlin");
MODULE_DESCRIPTION("Memory Manager");

int pid;

module_param(pid, int, 0);

unsigned long rss;
unsigned long swap;
unsigned long wss;

struct task_struct *task;

pte_t* pte_by_address(const struct mm_struct *const mm, const unsigned long address) {
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte = NULL;
	struct page *page = NULL;

	pgd = pgd_offset(mm, address);
	if (!pgd_present(*pgd))
		goto do_return;

	p4d = p4d_offset(pgd, address);
	if (!p4d_present(*p4d))
		goto do_return;

	pud = pud_offset(p4d, address);
	if (!pud_present(*pud))
		goto do_return;

	pmd = pmd_offset(pud, address);
	if (!pmd_present(*pmd))
		goto do_return;

	pte = pte_offset_kernel(pmd, address);
	if (!pte_present(*pte)){
		swap = swap + 1;
		goto do_return;
	}
	else 
		rss = rss + 1;

	page = pte_page(*pte);
do_return:
	return pte;
}

void count_pages(struct task_struct *ltask) {
	if (ltask != NULL) {
		const struct vm_area_struct *vma = ltask->mm->mmap;
		while (vma != NULL) {
			unsigned long address;
			for (address = vma->vm_start; address < vma->vm_end; address += PAGE_SIZE) {
				//if (pte_present(*pte_by_address(ltask->mm, address)))
				//	rss = rss + 1;
				//else
				//	swap = swap + 1;
				//rss = rss + 1;
				if (ptep_test_and_clear_young(vma, address, pte_by_address(ltask->mm, address)) == 1)
					wss = wss + 1;
			}

			vma = vma->vm_next;
		}
	}
}

int ptep_test_and_clear_young(struct vm_area_struct *vma, unsigned long addr, pte_t *ptep) {
	int ret = 0;
	if (pte_young(*ptep))
		ret = test_and_clear_bit(_PAGE_BIT_ACCESSED, (unsigned long *) &ptep->pte);
	return ret;
}


unsigned long timer_interval_ns = 10e9;
static struct hrtimer hr_timer;
enum hrtimer_restart timer_callback(struct hrtimer *timer_for_restart) {
	ktime_t currtime, interval;
	currtime = ktime_get();
	interval = ktime_set(0, timer_interval_ns);
	hrtimer_forward(timer_for_restart, currtime, interval);
	
	count_pages(task);
	rss = rss * PAGE_SIZE;
	rss = rss / 1024;
	wss = wss * PAGE_SIZE;
	wss = wss / 1024;
	swap = swap * PAGE_SIZE;
	swap = swap / 1024;
	printk(KERN_INFO "PID [%d]: RSS=%ld KB, SWAP=%ld KB, WSS=%ld KB", pid, rss, swap, wss);

	rss = 0;
	wss = 0;
	swap = 0;
	return HRTIMER_RESTART;
}



static int __init init_func(void) {
	printk(KERN_INFO "Starting memory manager for PID %d", pid);
	//for_each_process(ptr) {
	//	if (ptr->pid == pid) {
	//		task = ptr;
	//		printk(KERN_INFO "Found task with PID %d", task->pid);
	//	}
	//}
	
	//struct task_struct *task;
	task = pid_task(find_vpid(pid), PIDTYPE_PID);
	//page_by_address(task->mm, task->mm->mmap->vm_start);
	if (task == NULL) {
		printk(KERN_INFO "task NULL");
	}
	if (task != NULL) {
		//count_pages(task);
		ktime_t ktime;
		ktime = ktime_set(0, timer_interval_ns);
		hrtimer_init(&hr_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
		hr_timer.function = &timer_callback;
		hrtimer_start(&hr_timer, ktime, HRTIMER_MODE_REL);
	}
	//rss = rss * PAGE_SIZE;
	//rss = rss / 1024;
	//printk(KERN_INFO "[%d] RSS: %d", pid, rss);

	return 0;
}

static void __exit exit_func(void) {
	int ret;
	ret = hrtimer_cancel(&hr_timer);
	if (ret) printk(KERN_INFO "The timer was still in use");
	printk(KERN_INFO "Exiting memory manager");
}

module_init(init_func);
module_exit(exit_func);
