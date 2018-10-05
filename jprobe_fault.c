/*
   Source obtained from:
   https://github.com/pradykaushik/Jprobes
*/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/proc_fs.h>
#include <linux/time.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
//SUJAY:#include <asm/rtc.h>
#include <linux/ktime.h>

//SUJAY: Added these lines:
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <asm/tlbflush.h>

#define PTE_RESERVED_MASK	(_AT(pteval_t, 1) << 51)
#define PF_PROT	 (1<<0)
#define PF_RSVD	 (1<<3)
#define PF_INSTR (1<<4)

//structure to hold the information of the proc file
struct proc_dir_entry* my_proc_file;

//kernel buffer to store the result
static char* data_buffer = NULL;

//number of bytes written to data_buffer
static int number_of_bytes = 0;

//fetching the pid from command line arguments.
static int pid=0;
//module_param(pid, int, 0000);

//variable to keep track of number of times proc file was read.
static int temp_len=0;

unsigned long old_address=0;
unsigned long old_ip;

static struct task_struct * (*find_task_by_vpid_p)(int);


int make_page_entries_reserved(void)
{
	struct task_struct *tsk;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	
	find_task_by_vpid_p = (void *) kallsyms_lookup_name("find_task_by_vpid");
	tsk = find_task_by_vpid_p(pid);
	mm = tsk->mm;

	unsigned long i,k,l,m;
	unsigned int count = 0;
	pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
	pgd_t *base = mm->pgd;
	unsigned long address;
	
	unsigned long mask = _PAGE_USER | _PAGE_PRESENT;
	
	for(i=0;i<PTRS_PER_PGD;i++)
	{
		pgd = base + i;
		if((pgd_flags(*pgd) & mask) != mask)
			continue;
		for(k=0;k<PTRS_PER_PUD;k++)
		{
			pud = (pud_t *)pgd_page_vaddr(*pgd) + k;
			if((pud_flags(*pud) & mask) != mask)
				continue;
			for(l=0;l<PTRS_PER_PMD;l++)
			{
				pmd = (pmd_t *)pud_page_vaddr(*pud) + l;
				if((pmd_flags(*pmd) & mask) != mask)
					continue;
				for(m=0;m<PTRS_PER_PTE;m++)
				{
					pte = (pte_t *)pmd_page_vaddr(*pmd) + m;
					if(((pte_flags(*pte) & mask) != mask) || !(pte_flags(*pte) & _PAGE_BIT_RW))
						continue;
					address = (i<<PGDIR_SHIFT) + (k<<PUD_SHIFT) + (l<<PMD_SHIFT) + (m<<PAGE_SHIFT);
					//printk("addr:0x%lx\n",address);
					vma = find_vma(mm, address);
					if(vma && (vma->vm_start <= address) && (vma->vm_end >= address))
					{
						/* Important: For some reason, some PTE entries say the page is writable
						 * whereas VMA says that the region is not writable. So checking again
						 * to make sure page is writable (data page).
						 */
						if((vma->vm_flags & VM_WRITE) && !(vma->vm_flags & VM_EXEC))
						{
							*pte = pte_set_flags(*pte, PTE_RESERVED_MASK);
							count++;
							//printk("Modified a PTE\n");
						}
					}
				}
			}
		}
	}
	return count;
}

int my_handler(int _pid){ 
    int ret = 0;
    pid = _pid;
    printk(KERN_ALERT "Syscall intercepted pid=%d\n",pid);
    old_address = 0;
    ret = make_page_entries_reserved();
    if(ret == 0)
    	printk(KERN_ALERT "No page table entry modified.\n");
    jprobe_return(); 
} 

//function called when read() is called on the proc file
ssize_t my_proc_file_read(struct file* fileptr, char* user_buffer,
		size_t length, loff_t* offset){

	/* Send 0 if no more data to send: temp value is decreased
	base on the length of bytes read */
	if(length > temp_len)
		length = temp_len;
	temp_len = temp_len - length;	
	//need to copy the contents of the data buffer to user buffer
	copy_to_user(user_buffer, data_buffer, length);
	return length;	
}

/* my_do_page_fault is called on a page fault before __do_page_fault
 * is invoked.
 */
my_do_page_fault(struct pt_regs *regs, unsigned long error_code,
		unsigned long address)
{
	struct task_struct *tsk;
	struct mm_struct *mm;

	//checking if pid matches.
	if(current->pid == pid)
	{
		//need to concatenate data to the buffer.
		char temp[50] = {0};
		int size = snprintf(temp, 50, "virtual_address: 0x%lx, error_code=0x%x\n", address, error_code);
				
		struct vm_area_struct *vma;
		vma = find_vma(current->mm, address);
		if(!vma)
			printk(KERN_INFO "virtual address:0x%x VMA not valid\n", address);
		else if(vma->vm_start <= address)
		{
		printk(KERN_INFO "Virt addr:0x%lx,  ip=0x%lx\n", address, regs->ip);
		if(error_code & PF_RSVD)
		{
			printk("Induced Page Fault, address:0x%lx\n",address);
			pgd_t *pgd;
            p4d_t *p4d;
            pud_t *pud;
            pmd_t *pmd;
            pte_t *pte;

            pgd = pgd_offset(vma->vm_mm, address);
            p4d = p4d_offset(pgd, address);            
            if (!p4d_none(*p4d))
            {
                pud = pud_offset(p4d, address);
                if(!pud_none(*pud))
                {
                    pmd = pmd_offset(pud, address);
                    if(!pmd_none(*pmd))
                    {
                        pte = pte_offset_kernel(pmd, address);
                        if(!pte_none(*pte))
                        {
							*pte = pte_clear_flags(*pte, PTE_RESERVED_MASK);
                        }
                    }
                }
        	}			
		}
		if(old_address!=0 && old_address!=address && old_ip!=regs->ip)
		{
			pgd_t *pgd;
            p4d_t *p4d;
            pud_t *pud;
            pmd_t *pmd;
            pte_t *pte;

            pgd = pgd_offset(vma->vm_mm, old_address);
            
            p4d = p4d_offset(pgd, old_address);            
            if (!p4d || p4d_none(*p4d))
            	printk(KERN_ERR "Problem with P4D\n");
            else
            {
                pud = pud_offset(p4d, old_address);
                if(!pud || pud_none(*pud))
                    printk(KERN_ERR "Problem with PUD\n");
                else
                {
                    pmd = pmd_offset(pud, old_address);
                    if(!pmd || pmd_none(*pmd))
                        printk(KERN_ERR "Problem with PMD\n");
                    else
                    {
                        pte = pte_offset_kernel(pmd, old_address);
                        if(pte_none(*pte))
                            printk(KERN_ERR "Problem with PTE\n");
                        else
                        {
                            //printk(KERN_INFO "PTE contents = 0x%lx \n",pte_val(*pte));
							
							*pte = pte_set_flags(*pte, PTE_RESERVED_MASK);
							//flush_tlb_page(vma, old_address);
							__flush_tlb_all();
                        }
                    }
                }
        	}
        } 
        if(!(error_code & PF_INSTR))//
        {
	        old_address = address;     
	        old_ip = regs->ip;
	    }
	    else
	    	old_address = 0;
        }
                        
        number_of_bytes += (size+1);
		temp_len = number_of_bytes;

		//maybe we need to allocate memory.
		if(data_buffer == NULL){
			data_buffer = (char*)kzalloc(sizeof(char)*
				number_of_bytes, GFP_KERNEL);
		}
		else{
			data_buffer = (char*)krealloc(data_buffer, 
				number_of_bytes, GFP_KERNEL);
		}
		strcat(data_buffer, temp);
	}
	jprobe_return();
	return 0;
}


//defining the handler and the entry point of the fault handler.

static struct jprobe my_jprobe = {
	.entry = my_do_page_fault,
	.kp = {
		.symbol_name = "__do_page_fault",
	},
};

static struct jprobe pid_jprobe = {
	.entry = &my_handler, 
	.kp = {
		.symbol_name = "sys_syscall_test",
	},
};

//setting the function called when proc file is read.
static struct file_operations fops = {
	.read = &my_proc_file_read,
	.owner = THIS_MODULE,
};



//init module.
static int __init jprobe_init(void)
{
	int ret;
	//creating proc file.

	my_proc_file = proc_create("data_file", 0, NULL, &fops);

	//checking if proc file was created.
	if(my_proc_file == NULL){
		remove_proc_entry("data_file", NULL);
		printk(KERN_ERR "Error: Could not initialize /proc/%s file\n", "data_file");
		return -1;
	}

	//registering module.
	ret = register_jprobe(&my_jprobe);
	if (ret < 0) {
		printk(KERN_ERR "Error: Register_jprobe failed: %d\n", ret);
		return -1;
	}

	//registering module.
	ret = register_jprobe(&pid_jprobe);
	if (ret < 0) {
		printk(KERN_ERR "Error: Register pid_jprobe failed: %d\n", ret);
		return -1;
	}

	printk(KERN_INFO "Success: Planted jprobe at %p\n",my_jprobe.kp.addr);
	return 0;
}

//exit module.
static void __exit jprobe_exit(void)
{
	kfree(data_buffer);
	remove_proc_entry("data_file", NULL);
	unregister_jprobe(&my_jprobe);
	unregister_jprobe(&pid_jprobe);
	printk(KERN_INFO "jprobe unregistered\n");
}

module_init(jprobe_init);
module_exit(jprobe_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sujay");
MODULE_DESCRIPTION("Tracks page faults of a process");
