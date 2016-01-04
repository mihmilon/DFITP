#include <linux/cgroup.h>
#include <linux/cred.h>
DEFINE_SPINLOCK(cgroup_idr_lock);
DEFINE_SPINLOCK(release_agent_path_lock);
struct workqueue_struct *cgroup_destroy_wq;
struct workqueue_struct *cgroup_pidlist_destroy_wq;
#define SUBSYS(_x) [_x ## _cgrp_id] = &_x ## _cgrp_subsys,
#define SUBSYS(_x) [_x ## _cgrp_id] = #_x,
struct cgroup_root cgrp_dfl_root;
bool cgrp_dfl_root_visible;
bool cgroup_legacy_files_on_dfl;
unsigned int cgrp_dfl_root_inhibit_ss_mask;
LIST_HEAD(cgroup_roots);
int cgroup_root_count;
DEFINE_IDR(cgroup_hierarchy_idr);
u64 css_serial_nr_next = 1;
int need_forkexit_callback __read_mostly;
struct cftype cgroup_dfl_base_files[];
struct cftype cgroup_legacy_base_files[];
int rebind_subsystems(struct cgroup_root *dst_root,unsigned int ss_mask);
int cgroup_destroy_locked(struct cgroup *cgrp);
int create_css(struct cgroup *cgrp, struct cgroup_subsys *ss,bool visible);
void css_release(struct percpu_ref *ref);
void kill_css(struct cgroup_subsys_state *css);
int cgroup_addrm_files(struct cgroup *cgrp, struct cftype cfts[], bool is_add);
int cgroup_idr_alloc(struct idr *idr, void *ptr, int start, int end, gfp_t gfp_mask){
	int ret;
	idr_preload(gfp_mask);
	spin_lock_bh(&cgroup_idr_lock);
	ret = idr_alloc(idr, ptr, start, end, gfp_mask);
	spin_unlock_bh(&cgroup_idr_lock);
	idr_preload_end();
	return ret;
}
void *cgroup_idr_replace(struct idr *idr, void *ptr, int id){
	void *ret;
	spin_lock_bh(&cgroup_idr_lock);
	ret = idr_replace(idr, ptr, id);
	spin_unlock_bh(&cgroup_idr_lock);
	return ret;
}
void cgroup_idr_remove(struct idr *idr, int id){
	spin_lock_bh(&cgroup_idr_lock);
	idr_remove(idr, id);
	spin_unlock_bh(&cgroup_idr_lock);
}
struct cgroup *cgroup_parent(struct cgroup *cgrp){
	struct cgroup_subsys_state *parent_css = cgrp->self.parent;
	if (parent_css)
		return container_of(parent_css, struct cgroup, self);
	return NULL;
}
struct cgroup_subsys_state *cgroup_css(struct cgroup *cgrp, struct cgroup_subsys *ss){
	if (ss)
		return rcu_dereference_check(cgrp->subsys[ss->id], lockdep_is_held(&cgroup_mutex));
	else
		return &cgrp->self;
}
struct cgroup_subsys_state *cgroup_e_css(struct cgroup *cgrp, struct cgroup_subsys *ss){
	lockdep_assert_held(&cgroup_mutex);
	if (!ss)
		return &cgrp->self;
	if (!(cgrp->root->subsys_mask & (1 << ss->id)))
		return NULL;
	while (cgroup_parent(cgrp) && !(cgroup_parent(cgrp)->child_subsys_mask & (1 << ss->id))){
		cgrp = cgroup_parent(cgrp);
	}
	return cgroup_css(cgrp, ss);
}
struct cgroup_subsys_state *cgroup_get_e_css(struct cgroup *cgrp, struct cgroup_subsys *ss){
	struct cgroup_subsys_state *css;
	rcu_read_lock();
	do {
		css = cgroup_css(cgrp, ss);
		if (css && css_tryget_online(css))
			goto out_unlock;
		cgrp = cgroup_parent(cgrp);
	}while (cgrp);
	css = init_css_set.subsys[ss->id];
	css_get(css);
out_unlock:
	rcu_read_unlock();
	return css;
}
inline bool cgroup_is_dead(const struct cgroup *cgrp){
	return !(cgrp->self.flags & CSS_ONLINE);
}
struct cgroup_subsys_state *of_css(struct kernfs_open_file *of){
	struct cgroup *cgrp = of->kn->parent->priv;
	struct cftype *cft = of_cft(of);
	if (cft->ss)
		return rcu_dereference_raw(cgrp->subsys[cft->ss->id]);
	else
		return &cgrp->self;
}
bool cgroup_is_descendant(struct cgroup *cgrp, struct cgroup *ancestor){
	while (cgrp) {
		if (cgrp == ancestor)
			return true;
		cgrp = cgroup_parent(cgrp);
	}
	return false;
}
int notify_on_release(const struct cgroup *cgrp){
	return test_bit(CGRP_NOTIFY_ON_RELEASE, &cgrp->flags);
}
void cgroup_update_populated(struct cgroup *cgrp, bool populated){
	lockdep_assert_held(&css_set_rwsem);
	do {
		bool trigger;
		if (populated)
			trigger = !cgrp->populated_cnt++;
		else
			trigger = !--cgrp->populated_cnt;
		if (!trigger)
			break;
		if (cgrp->populated_kn)
			kernfs_notify(cgrp->populated_kn);
		cgrp = cgroup_parent(cgrp);
	} while (cgrp);
}
unsigned long css_set_hash(struct cgroup_subsys_state *css[]){
	unsigned long key = 0UL;
	struct cgroup_subsys *ss;
	int i;
	for_each_subsys(ss, i)
		key += (unsigned long)css[i];
	key = (key >> 16) ^ key;
	return key;
}
void put_css_set_locked(struct css_set *cset){
	struct cgrp_cset_link *link, *tmp_link;
	struct cgroup_subsys *ss;
	int ssid;
	lockdep_assert_held(&css_set_rwsem);
	if (!atomic_dec_and_test(&cset->refcount))
		return;
	for_each_subsys(ss, ssid)
		list_del(&cset->e_cset_node[ssid]);
	hash_del(&cset->hlist);
	css_set_count--;
	list_for_each_entry_safe(link, tmp_link, &cset->cgrp_links, cgrp_link) {
		struct cgroup *cgrp = link->cgrp;
		list_del(&link->cset_link);
		list_del(&link->cgrp_link);
		if (list_empty(&cgrp->cset_links)) {
			cgroup_update_populated(cgrp, false);
			check_for_release(cgrp);
		}
		kfree(link);
	}
	kfree_rcu(cset, rcu_head);
}
void put_css_set(struct css_set *cset){
	if (atomic_add_unless(&cset->refcount, -1, 1))
		return;
	down_write(&css_set_rwsem);
	put_css_set_locked(cset);
	up_write(&css_set_rwsem);
}
inline void get_css_set(struct css_set *cset){
	atomic_inc(&cset->refcount);
}
bool compare_css_sets(struct css_set *cset, struct css_set *old_cset, struct cgroup *new_cgrp, struct cgroup_subsys_state *template[]){
	struct list_head *l1, *l2;
	if (memcmp(template, cset->subsys, sizeof(cset->subsys)))
		return false;
	l1 = &cset->cgrp_links;
	l2 = &old_cset->cgrp_links;
	while (1) {
		struct cgrp_cset_link *link1, *link2;
		struct cgroup *cgrp1, *cgrp2;
		l1 = l1->next;
		l2 = l2->next;
		if (l1 == &cset->cgrp_links) {
			BUG_ON(l2 != &old_cset->cgrp_links);
			break;
		}
		else {
			BUG_ON(l2 == &old_cset->cgrp_links);
		}
		link1 = list_entry(l1, struct cgrp_cset_link, cgrp_link);
		link2 = list_entry(l2, struct cgrp_cset_link, cgrp_link);
		cgrp1 = link1->cgrp;
		cgrp2 = link2->cgrp;
		BUG_ON(cgrp1->root != cgrp2->root);
		if (cgrp1->root == new_cgrp->root) {
			if (cgrp1 != new_cgrp)
				return false;
		}
		else {
			if (cgrp1 != cgrp2)
				return false;
		}
	}
	return true;
}
struct css_set *find_existing_css_set(struct css_set *old_cset, struct cgroup *cgrp, struct cgroup_subsys_state *template[]){
	struct cgroup_root *root = cgrp->root;
	struct cgroup_subsys *ss;
	struct css_set *cset;
	unsigned long key;
	int i;
	for_each_subsys(ss, i) {
		if (root->subsys_mask & (1UL << i)) {
			template[i] = cgroup_e_css(cgrp, ss);
		}
		else {
			template[i] = old_cset->subsys[i];
		}
	}
	key = css_set_hash(template);
	hash_for_each_possible(css_set_table, cset, hlist, key) {
		if (!compare_css_sets(cset, old_cset, cgrp, template))
			continue;
		return cset;
	}
	return NULL;
}
void free_cgrp_cset_links(struct list_head *links_to_free){
	struct cgrp_cset_link *link, *tmp_link;
	list_for_each_entry_safe(link, tmp_link, links_to_free, cset_link) {
		list_del(&link->cset_link);
		kfree(link);
	}
}
 int allocate_cgrp_cset_links(int count, struct list_head *tmp_links){
	struct cgrp_cset_link *link;
	int i;
	INIT_LIST_HEAD(tmp_links);
	for (i = 0; i < count; i++) {
		link = kzalloc(sizeof(*link), GFP_KERNEL);
		if (!link) {
			free_cgrp_cset_links(tmp_links);
			return -ENOMEM;
		}
		list_add(&link->cset_link, tmp_links);
	}
	return 0;
}
void link_css_set(struct list_head *tmp_links, struct css_set *cset, struct cgroup *cgrp){
	struct cgrp_cset_link *link;
	BUG_ON(list_empty(tmp_links));
	if (cgroup_on_dfl(cgrp)){
		cset->dfl_cgrp = cgrp;
	}
	link = list_first_entry(tmp_links, struct cgrp_cset_link, cset_link);
	link->cset = cset;
	link->cgrp = cgrp;
	if (list_empty(&cgrp->cset_links)){
		cgroup_update_populated(cgrp, true);
	}
	list_move(&link->cset_link, &cgrp->cset_links);
	list_add_tail(&link->cgrp_link, &cset->cgrp_links);
}
struct css_set *find_css_set(struct css_set *old_cset, struct cgroup *cgrp){
	struct cgroup_subsys_state *template[CGROUP_SUBSYS_COUNT] = { };
	struct css_set *cset;
	struct list_head tmp_links;
	struct cgrp_cset_link *link;
	struct cgroup_subsys *ss;
	unsigned long key;
	int ssid;
	lockdep_assert_held(&cgroup_mutex);
	down_read(&css_set_rwsem);
	cset = find_existing_css_set(old_cset, cgrp, template);
	if (cset){
		get_css_set(cset);
	}
	up_read(&css_set_rwsem);
	if (cset){
		return cset;
	}
	cset = kzalloc(sizeof(*cset), GFP_KERNEL);
	if (!cset){
		return NULL;
	}
	if (allocate_cgrp_cset_links(cgroup_root_count, &tmp_links) < 0) {
		kfree(cset);
		return NULL;
	}
	atomic_set(&cset->refcount, 1);
	INIT_LIST_HEAD(&cset->cgrp_links);
	INIT_LIST_HEAD(&cset->tasks);
	INIT_LIST_HEAD(&cset->mg_tasks);
	INIT_LIST_HEAD(&cset->mg_preload_node);
	INIT_LIST_HEAD(&cset->mg_node);
	INIT_HLIST_NODE(&cset->hlist);
	memcpy(cset->subsys, template, sizeof(cset->subsys));
	down_write(&css_set_rwsem);
	list_for_each_entry(link, &old_cset->cgrp_links, cgrp_link) {
		struct cgroup *c = link->cgrp;
		if (c->root == cgrp->root){
			c = cgrp;
		}
	link_css_set(&tmp_links, cset, c);
	}
	BUG_ON(!list_empty(&tmp_links));
	css_set_count++;
	key = css_set_hash(cset->subsys);
	hash_add(css_set_table, &cset->hlist, key);
	for_each_subsys(ss, ssid);
	list_add_tail(&cset->e_cset_node[ssid], &cset->subsys[ssid]->cgroup->e_csets[ssid]);
	up_write(&css_set_rwsem);
	return cset;
}

struct cgroup_root *cgroup_root_from_kf(struct kernfs_root *kf_root){
	struct cgroup *root_cgrp = kf_root->kn->priv;
	return root_cgrp->root;
}
int cgroup_init_root_id(struct cgroup_root *root){
	int id;
	lockdep_assert_held(&cgroup_mutex);
	id = idr_alloc_cyclic(&cgroup_hierarchy_idr, root, 0, 0, GFP_KERNEL);
	if (id < 0)
		return id;
	root->hierarchy_id = id;
	return 0;
}
void cgroup_exit_root_id(struct cgroup_root *root){
	lockdep_assert_held(&cgroup_mutex);
	if (root->hierarchy_id) {
		idr_remove(&cgroup_hierarchy_idr, root->hierarchy_id);
		root->hierarchy_id = 0;
	}
}
int cgroup_populate_dir(struct cgroup *cgrp, unsigned int subsys_mask){
	struct cgroup_subsys *ss;
	int i, ret = 0;
	for_each_subsys(ss, i) {
		struct cftype *cfts;
		if (!(subsys_mask & (1 << i))){
			continue;
		}
		list_for_each_entry(cfts, &ss->cfts, node) {
			ret = cgroup_addrm_files(cgrp, cfts, true);
			if (ret < 0){
				goto err;
			}
		}
	}
	return 0;
	cgroup_clear_dir(cgrp, subsys_mask);
	return ret;
}
void cgroup_free_root(struct cgroup_root *root){
	if (root) {
		WARN_ON_ONCE(root->hierarchy_id);
		idr_destroy(&root->cgroup_idr);
		kfree(root);
	}
}
void cgroup_destroy_root(struct cgroup_root *root){
	struct cgroup *cgrp = &root->cgrp;
	struct cgrp_cset_link *link, *tmp_link;
	mutex_lock(&cgroup_mutex);
	BUG_ON(atomic_read(&root->nr_cgrps));
	BUG_ON(!list_empty(&cgrp->self.children));
	rebind_subsystems(&cgrp_dfl_root, root->subsys_mask);
	down_write(&css_set_rwsem);
	list_for_each_entry_safe(link, tmp_link, &cgrp->cset_links, cset_link) {
		list_del(&link->cset_link);
		list_del(&link->cgrp_link);
		kfree(link);
	}
	up_write(&css_set_rwsem);
	if (!list_empty(&root->root_list)) {
		list_del(&root->root_list);
		cgroup_root_count--;
	}
	cgroup_exit_root_id(root);
	mutex_unlock(&cgroup_mutex);
	kernfs_destroy_root(root->kf_root);
	cgroup_free_root(root);
}
 struct cgroup *cset_cgroup_from_root(struct css_set *cset, struct cgroup_root *root){
	struct cgroup *res = NULL;
	lockdep_assert_held(&cgroup_mutex);
	lockdep_assert_held(&css_set_rwsem);
	if (cset == &init_css_set) {
		res = &root->cgrp;
	}
	else {
		struct cgrp_cset_link *link;
		list_for_each_entry(link, &cset->cgrp_links, cgrp_link) {
			struct cgroup *c = link->cgrp;
			if (c->root == root) {
				res = c;
				break;
			}
		}
	}
	BUG_ON(!res);
	return res;
}
struct cgroup *task_cgroup_from_root(struct task_struct *task, struct cgroup_root *root){
	return cset_cgroup_from_root(task_css_set(task), root);
}
char *cgroup_file_name(struct cgroup *cgrp, const struct cftype *cft, char *buf){
	if (cft->ss && !(cft->flags & CFTYPE_NO_PREFIX) && !(cgrp->root->flags & CGRP_ROOT_NOPREFIX))
		snprintf(buf, CGROUP_FILE_NAME_MAX, "%s.%s", cft->ss->name, cft->name);
	else
		strncpy(buf, cft->name, CGROUP_FILE_NAME_MAX);
	return buf;
}
struct dentry *cgroup_mount(struct file_system_type *fs_type, int flags, const char *unused_dev_name, void *data){
	struct super_block *pinned_sb = NULL;
	struct cgroup_subsys *ss;
	struct cgroup_root *root;
	struct cgroup_sb_opts opts;
	struct dentry *dentry;
	int ret;
	int i;
	bool new_sb;
	mutex_lock(&cgroup_mutex);
	ret = parse_cgroupfs_options(data, &opts);
	if (opts.flags & CGRP_ROOT_SANE_BEHAVIOR) {
		cgrp_dfl_root_visible = true;
		root = &cgrp_dfl_root;
		cgroup_get(&root->cgrp);
		ret = 0;
		goto out_unlock;
	}
	if (!(opts.subsys_mask & (1 << i)) ||
	    ss->root == &cgrp_dfl_root)
		continue;
	if (!percpu_ref_tryget_live(&ss->root->cgrp.self.refcnt)) {
		mutex_unlock(&cgroup_mutex);
		msleep(10);
		ret = restart_syscall();
		goto out_free;
	}
	cgroup_put(&ss->root->cgrp);
	bool name_match = false;
	if (root == &cgrp_dfl_root)
		continue;
	if (opts.name) {
		if (strcmp(opts.name, root->name))
			continue;
		name_match = true;
	}
	if ((opts.subsys_mask || opts.none) &&
	    (opts.subsys_mask != root->subsys_mask)) {
		if (!name_match)
			continue;
		ret = -EBUSY;
		goto out_unlock;
	}
	if (root->flags ^ opts.flags)
		pr_warn("new mount options do not match the existing superblock, will be ignored\n");
	pinned_sb = kernfs_pin_sb(root->kf_root, NULL);
	if (!opts.subsys_mask && !opts.none) {
		ret = -EINVAL;
		goto out_unlock;
	}
	root = kzalloc(sizeof(*root), GFP_KERNEL);
	if (!root) {
		ret = -ENOMEM;
		goto out_unlock;
	}
	init_cgroup_root(root, &opts);
	ret = cgroup_setup_root(root, opts.subsys_mask);
	if (ret)
		cgroup_free_root(root);
out_unlock:
	mutex_unlock(&cgroup_mutex);
out_free:
	kfree(opts.release_agent);
	kfree(opts.name);
	return dentry;
}
umode_t cgroup_file_mode(const struct cftype *cft){
	umode_t mode = 0;
	if (cft->mode)
		return cft->mode;
	if (cft->read_u64 || cft->read_s64 || cft->seq_show)
		mode |= S_IRUGO;
	if (cft->write_u64 || cft->write_s64 || cft->write)
		mode |= S_IWUSR;
	return mode;
}
void cgroup_get(struct cgroup *cgrp){
	WARN_ON_ONCE(cgroup_is_dead(cgrp));
	css_get(&cgrp->self);
}
bool cgroup_tryget(struct cgroup *cgrp){
	return css_tryget(&cgrp->self);
}
void cgroup_put(struct cgroup *cgrp){
	css_put(&cgrp->self);
}
unsigned int cgroup_calc_child_subsys_mask(struct cgroup *cgrp, unsigned int subtree_control){
	struct cgroup *parent = cgroup_parent(cgrp);
	unsigned int cur_ss_mask = subtree_control;
	struct cgroup_subsys *ss;
	int ssid;
	lockdep_assert_held(&cgroup_mutex);
	if (!cgroup_on_dfl(cgrp))
		return cur_ss_mask;
	while (true) {
		unsigned int new_ss_mask = cur_ss_mask;
		for_each_subsys(ss, ssid)
			if (cur_ss_mask & (1 << ssid))
				new_ss_mask |= ss->depends_on;
		if (parent)
			new_ss_mask &= parent->child_subsys_mask;
		else
			new_ss_mask &= cgrp->root->subsys_mask;

		if (new_ss_mask == cur_ss_mask)
			break;
		cur_ss_mask = new_ss_mask;
	}
	return cur_ss_mask;
}
void cgroup_refresh_child_subsys_mask(struct cgroup *cgrp){
	cgrp->child_subsys_mask = cgroup_calc_child_subsys_mask(cgrp, cgrp->subtree_control);
}
void cgroup_kn_unlock(struct kernfs_node *kn){
	struct cgroup *cgrp;
	if (kernfs_type(kn) == KERNFS_DIR)
		cgrp = kn->priv;
	else
		cgrp = kn->parent->priv;
	mutex_unlock(&cgroup_mutex);
	kernfs_unbreak_active_protection(kn);
	cgroup_put(cgrp);
}
struct cgroup *cgroup_kn_lock_live(struct kernfs_node *kn){
	struct cgroup *cgrp;
	if (kernfs_type(kn) == KERNFS_DIR)
		cgrp = kn->priv;
	else
		cgrp = kn->parent->priv;
	if (!cgroup_tryget(cgrp))
		return NULL;
	kernfs_break_active_protection(kn);
	mutex_lock(&cgroup_mutex);
	if (!cgroup_is_dead(cgrp))
		return cgrp;
	cgroup_kn_unlock(kn);
	return NULL;
}
void init_cgroup_root(struct cgroup_root *root, struct cgroup_sb_opts *opts){
	struct cgroup *cgrp = &root->cgrp;
	INIT_LIST_HEAD(&root->root_list);
	atomic_set(&root->nr_cgrps, 1);
	cgrp->root = root;
	init_cgroup_housekeeping(cgrp);
	idr_init(&root->cgroup_idr);
	root->flags = opts->flags;
	if (opts->release_agent)
		strcpy(root->release_agent_path, opts->release_agent);
	if (opts->name)
		strcpy(root->name, opts->name);
	if (opts->cpuset_clone_children)
		set_bit(CGRP_CPUSET_CLONE_CHILDREN, &root->cgrp.flags);
}
void cgroup_rm_file(struct cgroup *cgrp, const struct cftype *cft){
	char name[CGROUP_FILE_NAME_MAX];
	lockdep_assert_held(&cgroup_mutex);
	kernfs_remove_by_name(cgrp->kn, cgroup_file_name(cgrp, cft, name));
}
void cgroup_clear_dir(struct cgroup *cgrp, unsigned int subsys_mask){
	struct cgroup_subsys *ss;
	int i;
	for_each_subsys(ss, i) {
		struct cftype *cfts;
		if (!(subsys_mask & (1 << i)))
			continue;
		list_for_each_entry(cfts, &ss->cfts, node)
			cgroup_addrm_files(cgrp, cfts, false);
	}
}
int rebind_subsystems(struct cgroup_root *dst_root, unsigned int ss_mask){
	struct cgroup_subsys *ss;
	unsigned int tmp_ss_mask;
	int ssid, i, ret;
	lockdep_assert_held(&cgroup_mutex);
	if (!(ss_mask & (1 << ssid)))
			continue;
	if (css_next_child(NULL, cgroup_css(&ss->root->cgrp, ss))){
		return -EBUSY;
	}
	if (ss->root != &cgrp_dfl_root && dst_root != &cgrp_dfl_root)
			return -EBUSY;
	tmp_ss_mask = ss_mask;
	if (dst_root == &cgrp_dfl_root){
		tmp_ss_mask &= ~cgrp_dfl_root_inhibit_ss_mask;
	}
	ret = cgroup_populate_dir(&dst_root->cgrp, tmp_ss_mask);
	if (ret) {
		if (dst_root != &cgrp_dfl_root)
			return ret;
		if (cgrp_dfl_root_visible) {
			pr_warn("failed to create files (%d) while rebinding 0x%x to default root\n",
				ret, ss_mask);
			pr_warn("you may retry by moving them to a different hierarchy and unbinding\n");
		}
	}
	if (ss_mask & (1 << ssid)){
		cgroup_clear_dir(&ss->root->cgrp, 1 << ssid);
	}
	for_each_subsys(ss, ssid) {
		struct cgroup_root *src_root;
		struct cgroup_subsys_state *css;
		struct css_set *cset;
		if (!(ss_mask & (1 << ssid)))
			continue;
		src_root = ss->root;
		css = cgroup_css(&src_root->cgrp, ss);
		WARN_ON(!css || cgroup_css(&dst_root->cgrp, ss));
		RCU_INIT_POINTER(src_root->cgrp.subsys[ssid], NULL);
		rcu_assign_pointer(dst_root->cgrp.subsys[ssid], css);
		ss->root = dst_root;
		css->cgroup = &dst_root->cgrp;
		down_write(&css_set_rwsem);
		list_move_tail(&cset->e_cset_node[ss->id], &dst_root->cgrp.e_csets[ss->id]);
		up_write(&css_set_rwsem);
		src_root->subsys_mask &= ~(1 << ssid);
		src_root->cgrp.subtree_control &= ~(1 << ssid);
		cgroup_refresh_child_subsys_mask(&src_root->cgrp);
		dst_root->subsys_mask |= 1 << ssid;
		if (dst_root != &cgrp_dfl_root) {
			dst_root->cgrp.subtree_control |= 1 << ssid;
			cgroup_refresh_child_subsys_mask(&dst_root->cgrp);
		}
		if (ss->bind)
			ss->bind(css);
	}
	kernfs_activate(dst_root->cgrp.kn);
	return 0;
}
int cgroup_show_options(struct seq_file *seq, struct kernfs_root *kf_root){
	struct cgroup_root *root = cgroup_root_from_kf(kf_root);
	struct cgroup_subsys *ss;
	int ssid;
	for_each_subsys(ss, ssid)
		if (root->subsys_mask & (1 << ssid))
			seq_printf(seq, ",%s", ss->name);
	if (root->flags & CGRP_ROOT_NOPREFIX)
		seq_puts(seq, ",noprefix");
	if (root->flags & CGRP_ROOT_XATTR)
		seq_puts(seq, ",xattr");
	spin_lock(&release_agent_path_lock);
	if (strlen(root->release_agent_path))
		seq_printf(seq, ",release_agent=%s", root->release_agent_path);
	spin_unlock(&release_agent_path_lock);
	if (test_bit(CGRP_CPUSET_CLONE_CHILDREN, &root->cgrp.flags))
		seq_puts(seq, ",clone_children");
	if (strlen(root->name))
		seq_printf(seq, ",name=%s", root->name);
	return 0;
}
int parse_cgroupfs_options(char *data, struct cgroup_sb_opts *opts){
	char *token, *o = data;
	bool all_ss = false, one_ss = false;
	unsigned int mask = -1U;
	struct cgroup_subsys *ss;
	int nr_opts = 0;
	int i;
	memset(opts, 0, sizeof(*opts));
	while ((token = strsep(&o, ",")) != NULL) {
		nr_opts++;
		if (!*token)
			return -EINVAL;
		if (!strcmp(token, "none")) {
			opts->none = true;
			continue;
		}
		if (!strcmp(token, "all")) {
			if (one_ss)
				return -EINVAL;
			all_ss = true;
			continue;
		}
		if (!strcmp(token, "__DEVEL__sane_behavior")) {
			opts->flags |= CGRP_ROOT_SANE_BEHAVIOR;
			continue;
		}
		if (!strcmp(token, "noprefix")) {
			opts->flags |= CGRP_ROOT_NOPREFIX;
			continue;
		}
		if (!strcmp(token, "clone_children")) {
			opts->cpuset_clone_children = true;
			continue;
		}
		if (!strcmp(token, "xattr")) {
			opts->flags |= CGRP_ROOT_XATTR;
			continue;
		}
		if (!strncmp(token, "release_agent=", 14)) {
			if (opts->release_agent)
				return -EINVAL;
			opts->release_agent =
				kstrndup(token + 14, PATH_MAX - 1, GFP_KERNEL);
			if (!opts->release_agent)
				return -ENOMEM;
			continue;
		}
		if (!strncmp(token, "name=", 5)) {
			const char *name = token + 5;
			if (!strlen(name))
				return -EINVAL;
			for (i = 0; i < strlen(name); i++) {
				char c = name[i];
				if (isalnum(c))
					continue;
				if ((c == '.') || (c == '-') || (c == '_'))
					continue;
				return -EINVAL;
			}
			if (opts->name)
				return -EINVAL;
			opts->name = kstrndup(name,
					      MAX_CGROUP_ROOT_NAMELEN - 1,
					      GFP_KERNEL);
			if (!opts->name)
				return -ENOMEM;

			continue;
		}
		for_each_subsys(ss, i) {
			if (strcmp(token, ss->name))
				continue;
			if (ss->disabled)
				continue;
			if (all_ss)
				return -EINVAL;
			opts->subsys_mask |= (1 << i);
			one_ss = true;
			break;
		}
		if (i == CGROUP_SUBSYS_COUNT)
			return -ENOENT;
	}
	if (opts->flags & CGRP_ROOT_SANE_BEHAVIOR) {
		pr_warn("sane_behavior: this is still under development and its behaviors will change, proceed at your own risk\n");
		if (nr_opts != 1) {
			pr_err("sane_behavior: no other mount options allowed\n");
			return -EINVAL;
		}
		return 0;
	}
	if (all_ss || (!one_ss && !opts->none && !opts->name))
		for_each_subsys(ss, i)
			if (!ss->disabled)
				opts->subsys_mask |= (1 << i);
	if (!opts->subsys_mask && !opts->name)
		return -EINVAL;
	if ((opts->flags & CGRP_ROOT_NOPREFIX) && (opts->subsys_mask & mask))
		return -EINVAL;
	if (opts->subsys_mask && opts->none)
		return -EINVAL;
	return 0;
}
int cgroup_remount(struct kernfs_root *kf_root, int *flags, char *data){
	int ret = 0;
	struct cgroup_root *root = cgroup_root_from_kf(kf_root);
	struct cgroup_sb_opts opts;
	unsigned int added_mask, removed_mask;
	if (root == &cgrp_dfl_root) {
		pr_err("remount is not allowed\n");
		return -EINVAL;
	}
	mutex_lock(&cgroup_mutex);
	ret = parse_cgroupfs_options(data, &opts);
	if (ret)
		goto out_unlock;
	if (opts.subsys_mask != root->subsys_mask || opts.release_agent)
		pr_warn("option changes via remount are deprecated (pid=%d comm=%s)\n",
			task_tgid_nr(current), current->comm);
	added_mask = opts.subsys_mask & ~root->subsys_mask;
	removed_mask = root->subsys_mask & ~opts.subsys_mask;
	if ((opts.flags ^ root->flags) ||
	    (opts.name && strcmp(opts.name, root->name))) {
		pr_err("option or name mismatch, new: 0x%x \"%s\", old: 0x%x \"%s\"\n",
		       opts.flags, opts.name ?: "", root->flags, root->name);
		ret = -EINVAL;
		goto out_unlock;
	}
	if (!list_empty(&root->cgrp.self.children)) {
		ret = -EBUSY;
		goto out_unlock;
	}
	ret = rebind_subsystems(root, added_mask);
	if (ret)
		goto out_unlock;
	rebind_subsystems(&cgrp_dfl_root, removed_mask);
	if (opts.release_agent) {
		spin_lock(&release_agent_path_lock);
		strcpy(root->release_agent_path, opts.release_agent);
		spin_unlock(&release_agent_path_lock);
	}
 out_unlock:
	kfree(opts.release_agent);
	kfree(opts.name);
	mutex_unlock(&cgroup_mutex);
	return ret;
}
void cgroup_enable_task_cg_lists(void){
	struct task_struct *p, *g;
	down_write(&css_set_rwsem);
	if (use_task_css_set_links)
		goto out_unlock;
	use_task_css_set_links = true;
	read_lock(&tasklist_lock);
	do_each_thread(g, p) {
		WARN_ON_ONCE(!list_empty(&p->cg_list) ||
			     task_css_set(p) != &init_css_set);
		spin_lock_irq(&p->sighand->siglock);
		if (!(p->flags & PF_EXITING)) {
			struct css_set *cset = task_css_set(p);

			list_add(&p->cg_list, &cset->tasks);
			get_css_set(cset);
		}
		spin_unlock_irq(&p->sighand->siglock);
	} while_each_thread(g, p);
	read_unlock(&tasklist_lock);
out_unlock:
	up_write(&css_set_rwsem);
}
void init_cgroup_housekeeping(struct cgroup *cgrp){
	struct cgroup_subsys *ss;
	int ssid;
	INIT_LIST_HEAD(&cgrp->self.sibling);
	INIT_LIST_HEAD(&cgrp->self.children);
	INIT_LIST_HEAD(&cgrp->cset_links);
	INIT_LIST_HEAD(&cgrp->pidlists);
	mutex_init(&cgrp->pidlist_mutex);
	cgrp->self.cgroup = cgrp;
	cgrp->self.flags |= CSS_ONLINE;
	init_waitqueue_head(&cgrp->offline_waitq);
	INIT_WORK(&cgrp->release_agent_work, cgroup_release_agent);
}
int cgroup_setup_root(struct cgroup_root *root, unsigned int ss_mask){
	LIST_HEAD(tmp_links);
	struct cgroup *root_cgrp = &root->cgrp;
	struct cftype *base_files, css_set *cset;
	int i, ret;
	lockdep_assert_held(&cgroup_mutex);
	ret = cgroup_idr_alloc(&root->cgroup_idr, root_cgrp, 1, 2, GFP_NOWAIT);
	root_cgrp->kn = root->kf_root->kn;
	if (root == &cgrp_dfl_root){
		ss_mask = cgroup_dfl_base_files;
	}
	else
		ss_mask = cgroup_legacy_base_files;
	ret = cgroup_addrm_files(root_cgrp, ss_mask, true);
	if (ret)
		goto destroy_root;
	ret = rebind_subsystems(root, ss_mask);
	if (ret)
		goto destroy_root;
	list_add(&root->root_list, &cgroup_roots);
	cgroup_root_count++;
	down_write(&css_set_rwsem);
	hash_for_each(css_set_table, i, cset, hlist)
	link_css_set(&tmp_links, cset, root_cgrp);
	up_write(&css_set_rwsem);
	BUG_ON(!list_empty(&root_cgrp->self.children));
	BUG_ON(atomic_read(&root->nr_cgrps) != 1);
	kernfs_activate(root_cgrp->kn);
	ret = 0;
	goto out;
destroy_root:
	kernfs_destroy_root(root->kf_root);
	root->kf_root = NULL;
exit_root_id:
	cgroup_exit_root_id(root);
cancel_ref:
	percpu_ref_exit(&root_cgrp->self.refcnt);
out:
	free_cgrp_cset_links(&tmp_links);
	return ret;
}
void cgroup_kill_sb(struct super_block *sb){
	struct kernfs_root *kf_root = kernfs_root_from_sb(sb);
	struct cgroup_root *root = cgroup_root_from_kf(kf_root);
	if (!list_empty(&root->cgrp.self.children) ||
	    root == &cgrp_dfl_root)
		cgroup_put(&root->cgrp);
	else
		percpu_ref_kill(&root->cgrp.self.refcnt);
	kernfs_kill_sb(sb);
}