/*
   Source obtained from:
   https://github.com/pradykaushik/Jprobes
*/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <asm/uaccess.h>

//SUJAY: Added these lines:
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <asm/tlbflush.h>

#define PTE_RESERVED_MASK	(_AT(pteval_t, 1) << 51)
#define PF_PROT	 (1<<0)
#define PF_RSVD	 (1<<3)
#define PF_INSTR (1<<4)

/* Function declarations */
static void my_do_page_fault(struct pt_regs *regs, unsigned long error_code, unsigned long address);
int syscall_handler(int _pid);
ssize_t pgfault_file_read(struct file* fileptr, char* user_buffer, size_t length, loff_t* offset);

//structure to hold the information of the proc file
struct proc_dir_entry* pgfault_file;

//kernel buffer to store the result
static char* data_buffer = NULL;

//number of bytes written to data_buffer
static int number_of_bytes = 0;

//fetching the pid from command line arguments.
static int pid = -1;

//variable to keep track of number of times proc file was read.
static int temp_len=0;

//variables to keep track of old fault address and old Instruction Pointer
unsigned long prev_address=0,old_prev=0, new_prev=0;

static struct task_struct* (*find_task_by_vpid_p)(int);
static struct mm_struct* (*get_task_mm_p)(struct task_struct *task);
static void (*mmput_p)(struct mm_struct *);
static void (*flush_tlb_mm_range_p)(struct mm_struct *mm, unsigned long start,
				unsigned long end, unsigned long vmflag);

//defining the handler and the entry point of the fault handler.
static struct jprobe pgfault_jprobe = {
	.entry = my_do_page_fault,
	.kp = {
		.symbol_name = "__do_page_fault",
	},
};

//Intercepting the syscall to capture the pid and modify the PTEs 
static struct jprobe syscall_jprobe = {
	.entry = &syscall_handler, 
	.kp = {
		.symbol_name = "sys_syscall_test",
	},
};

//setting the function called when proc file is read.
static struct file_operations fops = {
	.read = &pgfault_file_read,
	.owner = THIS_MODULE,
};


int make_page_entries_reserved(bool reserved)
{
	struct task_struct *tsk;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	
	unsigned long i,k,l,m;
	unsigned int count = 0;
	pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
	unsigned long address;
	
	unsigned long mask = _PAGE_USER | _PAGE_PRESENT;
	
	tsk = find_task_by_vpid_p(pid);
	
	/*
	 * Need to make sure that mm is valid before trying to access.
	 * Previously it was tsk->mm; if the process gets killed, tsk is NULL
	 * and tsk->mm will return in an error.
	 */	
	mm = get_task_mm_p(tsk);
	if(!mm)
		return 0;
	/* 
	 * Had to remove P4D because it is not used in 4 level tables,
	 * which is the case with current Linux kernel. Using it caused problems.
	 */
	for(i=0;i<PTRS_PER_PGD;i++)
	{
		pgd = mm->pgd + i;
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
					if((pte_flags(*pte) & mask) != mask)
						continue;
					address = (i<<PGDIR_SHIFT) + (k<<PUD_SHIFT) + (l<<PMD_SHIFT) + (m<<PAGE_SHIFT);
					vma = find_vma(mm, address);
					if(vma && (vma->vm_start <= address) && (vma->vm_end >= address))
					{
						/* 
						 * For now, just track the code pages.
						 */
						if(vma->vm_flags & VM_EXEC)
						{
							spin_lock(&mm->page_table_lock);
							if(reserved)
								*pte = pte_set_flags(*pte, PTE_RESERVED_MASK);
							else
								*pte = pte_clear_flags(*pte, PTE_RESERVED_MASK);
							spin_unlock(&mm->page_table_lock);
							flush_tlb_mm_range_p(mm, address, address+PAGE_SIZE, VM_NONE);
							count++;
							//printk("Modified a PTE\n");
						}
					}
				}
			}
		}
	}
	mmput_p(mm);
	
	return count;
}

/*
 * Syscall 333 intercepted by this handler
 */
int syscall_handler(int _pid)
{ 
    int ret = 0;
        
    prev_address = 0;
    old_prev = 0;
    new_prev = 0;
    number_of_bytes=0;
    
    printk(KERN_ALERT "Syscall intercepted pid=%d\n",_pid);
    
    if(_pid == -1)
   	{
   		current->mm->cca_en = 0;
   		ret = make_page_entries_reserved(false);
	   	if(ret == 0)
   			printk(KERN_ALERT "No page table entry cleared.\n");   		
		else
   			printk(KERN_INFO "Cleared %d entries\n", ret);
		pid = _pid;
		
   		jprobe_return();
   	}
   	
    pid = _pid;
 
   	ret = make_page_entries_reserved(true);
   	if(ret == 0)
   		printk(KERN_ALERT "No page table entry modified.\n");
   	else
   		printk(KERN_INFO "Modified %d entries\n", ret);
    jprobe_return(); 
} 

//function called when read() is called on the proc file
ssize_t pgfault_file_read(struct file* fileptr, char* user_buffer, size_t length, loff_t* offset)
{
	/* Send 0 if no more data to send: temp value is decreased
	base on the length of bytes read */
	if(length > temp_len)
		length = temp_len;
	temp_len = temp_len - length;	
	//need to copy the contents of the data buffer to user buffer
	copy_to_user(user_buffer, data_buffer, length);
	return length;	
}

/* 
 * my_do_page_fault is called on a page fault before __do_page_fault
 * is invoked.
 */
static void my_do_page_fault(struct pt_regs *regs, unsigned long error_code, unsigned long address)
{
	struct vm_area_struct *vma;

	//checking if pid matches.
	if(current->pid == pid)
	{
		/*
		int size = snprintf(temp, 20, "0x%lx\n", (address & ~0xFFF));
		number_of_bytes += (size+1);
		temp_len = number_of_bytes;

		//maybe we need to allocate memory.
		if(data_buffer == NULL)
			data_buffer = (char*)kzalloc(sizeof(char)*number_of_bytes, GFP_KERNEL);
		else
			data_buffer = (char*)krealloc(data_buffer, number_of_bytes, GFP_KERNEL);
		strcat(data_buffer, temp);
		*/
	
		//need to concatenate data to the buffer.
		char temp[50] = {0};
				
		vma = find_vma(current->mm, address);
		if(!vma)
			printk(KERN_INFO "virtual address:0x%x VMA not valid\n", address);
		else if(vma->vm_start <= address)
		{
			if(error_code & PF_INSTR)
				printk(KERN_INFO "0x%lx\n", (address & ~0xFFF));
			
			/* If the fault occurred with the PF_RSVD bit set, we need to 
			 * handle the fault as the default handler is not designed to
			 * handle this.
			 */
			if(error_code & PF_RSVD)
			{
				//if(error_code & PF_INSTR)
				//	printk("Induced Page Fault\n");
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
	                        	spin_lock(&vma->vm_mm->page_table_lock);
								*pte = pte_clear_flags(*pte, PTE_RESERVED_MASK);
								spin_unlock(&vma->vm_mm->page_table_lock);
	                        }
	                    }
	                }
	        	}			
			}
			
			/* Important: below checks make sure that we don't get stuck at a particular 
			 * address. The IP check is done because some instructions in x86 can access
			 * 2 memory addresses. Example: MOVS or move string takes two pointers: source
			 * address and destination address. So we need to check if Instruction pointer
			 * is same as last fault.
			 */
			if((old_prev == prev_address) && (new_prev == address))
				printk(KERN_ERR "Pattern detected\n");
			else if(prev_address!=0 && (vma->vm_flags & VM_EXEC))
			{
				pgd_t *pgd;
	            p4d_t *p4d;
	            pud_t *pud;
	            pmd_t *pmd;
	            pte_t *pte;
	
	            pgd = pgd_offset(vma->vm_mm, prev_address);
	            
	            p4d = p4d_offset(pgd, prev_address);            
	            if (!p4d || p4d_none(*p4d))
	            	printk(KERN_ERR "Problem with P4D\n");
	            else
	            {
	                pud = pud_offset(p4d, prev_address);
	                if(!pud || pud_none(*pud))
	                    printk(KERN_ERR "Problem with PUD\n");
	                else
	                {
	                    pmd = pmd_offset(pud, prev_address);
	                    if(!pmd || pmd_none(*pmd))
	                        printk(KERN_ERR "Problem with PMD\n");
	                    else
	                    {
	                        pte = pte_offset_kernel(pmd, prev_address);
	                        if(pte_none(*pte))
	                            printk(KERN_ERR "Problem with PTE\n");
	                        else
	                        {
		                        spin_lock(&vma->vm_mm->page_table_lock);
				  				*pte = pte_set_flags(*pte, PTE_RESERVED_MASK);
								spin_unlock(&vma->vm_mm->page_table_lock);			  				
				  				/* 
				  				 * flush_tlb_page symbol not found,
				  				 * need to find a better workaround
				  				 */
								//flush_tlb_page(vma, prev_address);
								flush_tlb_mm_range_p(vma->vm_mm, prev_address, prev_address+PAGE_SIZE, VM_NONE);
								//__flush_tlb_all();
	                        }
	                    }
	                }
	        	} 
	        }
        	old_prev = new_prev;
			new_prev = prev_address;
			if((old_prev == prev_address) && (new_prev == address))
				prev_address = 0;
			else
				prev_address = address; 
	    }
	}
	jprobe_return();
}
	
//init module.
static int __init jprobe_init(void)
{
	int ret;
	
	//creating proc file.
	pgfault_file = proc_create("pgfault_file", 0, NULL, &fops);

	//checking if proc file was created.
	if(pgfault_file == NULL){
		remove_proc_entry("pgfault_file", NULL);
		printk(KERN_ERR "Error: Could not initialize /proc/%s file\n", "pgfault_file");
		return -1;
	}

	//registering module.
	ret = register_jprobe(&pgfault_jprobe);
	if (ret < 0) {
		printk(KERN_ERR "Error: Register_jprobe failed: %d\n", ret);
		return -1;
	}

	//registering module.
	ret = register_jprobe(&syscall_jprobe);
	if (ret < 0) {
		printk(KERN_ERR "Error: Register pid_jprobe failed: %d\n", ret);
		return -1;
	}
	
	/* 
	 * Below symbols seem to be not exported from the Linux kernel.
	 * So not able to use it directly. A workaround is to lookup the name
	 * and use a function pointer.
	 */
	flush_tlb_mm_range_p = (void *) kallsyms_lookup_name("flush_tlb_mm_range");
	find_task_by_vpid_p = (void *) kallsyms_lookup_name("find_task_by_vpid");
	get_task_mm_p = kallsyms_lookup_name("get_task_mm");
	mmput_p = (void *)kallsyms_lookup_name("mmput");

//	printk(KERN_INFO "Success: Module Initiated\n");
	return 0;
}

//exit module.
static void __exit jprobe_exit(void)
{
	kfree(data_buffer);
	remove_proc_entry("pgfault_file", NULL);
	unregister_jprobe(&pgfault_jprobe);
	unregister_jprobe(&syscall_jprobe);
	printk(KERN_INFO "Module exited\n");
}

module_init(jprobe_init);
module_exit(jprobe_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sujay");
MODULE_DESCRIPTION("Tracks page faults of a process");
