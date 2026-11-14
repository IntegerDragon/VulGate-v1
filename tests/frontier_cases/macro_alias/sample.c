#define expand_stack(vma, addr) expand_stack_locked(vma, addr, false)

int expand_stack_locked(struct vm_area_struct *vma, unsigned long addr, bool write_locked)
{
    if (!(vma->vm_flags & VM_GROWSDOWN))
        return -EINVAL;
    grow(vma);
    return 0;
}

struct vm_area_struct *find_extend(struct mm_struct *mm, unsigned long addr)
{
    if (expand_stack_locked(vma, addr, false))
        return NULL;
    return vma;
}
