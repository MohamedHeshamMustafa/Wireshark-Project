#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <thread>
#include <vector>
#include <deque>
#include <algorithm>
#include <boost/thread/sync_queue.hpp>
#include <gtkmm.h>

#include "packet_model.h"
#include "packet.h"

using namespace std;
using namespace Gtk;
using namespace Gdk;
using namespace Glib;
using namespace sigc;

void ui_bind_setup();
void ui_callback_setup();
void ui_setup();
void setup();
void on_open_clicked();
void on_close_clicked();
void on_close_cleanup();
void on_save_clicked();
void on_start_clicked();
void on_stop_clicked();
void on_restart_clicked();
void on_about_clicked();
void on_row_selected();
void show_error_message(string msg);
int find_update_alldevs();
int start_sniff(const char *const dev);
void update_packets();

extern const char *const ui;
extern const char *const icon;
extern const char *const start_icon;
extern const char *const stop_icon;
extern const char *const restart_icon;
extern const char *const open_icon;
extern const char *const save_icon;
extern const char *const close_icon;
extern const char *const error_icon;
extern const size_t icon_size;
extern const size_t start_icon_size;
extern const size_t stop_icon_size;
extern const size_t restart_icon_size;
extern const size_t open_icon_size;
extern const size_t save_icon_size;
extern const size_t close_icon_size;
extern const size_t error_icon_size;

RefPtr<Application> app;

ApplicationWindow *main_application_window;
Stack *stack_window;
Box   *page1;
Paned *page2;

ImageMenuItem *open_menuitem;
ImageMenuItem *close_menuitem;
ImageMenuItem *save_menuitem;
ImageMenuItem *quit_menuitem;
MenuItem      *start_menuitem;
MenuItem      *stop_menuitem;
MenuItem      *restart_menuitem;
ImageMenuItem *about_menuitem;

ToolButton *start_toolbutton;
ToolButton *stop_toolbutton;
ToolButton *restart_toolbutton;
ToolButton *open_toolbutton;
ToolButton *save_toolbutton;
ToolButton *close_toolbutton;

ListBox *alldevs_listbox;
TreeView *ltreeview;
TreeView *ttreeview;
TextView *btextview;

RefPtr<Pixbuf> icon_pixbuf;
Image *error_icon_image;

ListModelColumns  lcol;
RefPtr<ListStore> lmodel;
TreeModelColumns  tcol;
RefPtr<TreeStore> tmodel;

std::deque       <eth_packet_t> dqpackets;
boost::sync_queue<eth_packet_t> *qpackets;

connection update_alldevs;
Dispatcher dispatcher;
thread *sniff_thread;
uint32_t npackets;
struct timespec ts;
pcap_t *handle;
pcap_dumper_t *pd;
char errbuf[PCAP_ERRBUF_SIZE+1];

#define UPDATE_ALLDEVS_INTERVAL 2
#define SNAPLEN 65535

#define label_from_listboxrow(lbr) \
	(((Label *) (lbr)->get_child())->get_label())

#define c_str_from_selected_row(lb) \
	(label_from_listboxrow((lb)->get_selected_row()).c_str())

#define get_error_string(d, s, h) \
	(string((d)) + ": " + pcap_statustostr((s)) + "\n(" + pcap_geterr((h)) + ")")

#define get_pixbuf_from_icon(l, i, is) \
	(((l) = PixbufLoader::create()), \
	(l)->write((const guint8 *) (i), (is)), \
	(l)->close(), \
	(l)->get_pixbuf())

#define toolbutton_setup(tb, tbi, tbis) { \
	RefPtr<PixbufLoader> loader; \
	Image *image = new Image(get_pixbuf_from_icon(loader, tbi, tbis)); \
	(tb)->set_icon_widget(*image); \
	image->show(); \
}

int main()
{
	app = Application::create();
	ui_bind_setup();
	ui_callback_setup();
	ui_setup();
	setup();
	return app->run(*main_application_window);
}

void ui_bind_setup()
{
	RefPtr<Builder> builder = Builder::create_from_string(ui);

	builder->get_widget("main_application_window", main_application_window);
	builder->get_widget("stack_window", stack_window);
	builder->get_widget("page1", page1);
	builder->get_widget("page2", page2);

	builder->get_widget("open_menuitem"   , open_menuitem);
	builder->get_widget("close_menuitem"  , close_menuitem);
	builder->get_widget("save_menuitem"   , save_menuitem);
	builder->get_widget("quit_menuitem"   , quit_menuitem);
	builder->get_widget("start_menuitem"  , start_menuitem);
	builder->get_widget("stop_menuitem"   , stop_menuitem);
	builder->get_widget("restart_menuitem", restart_menuitem);
	builder->get_widget("about_menuitem"  , about_menuitem);

	builder->get_widget("start_toolbutton"  , start_toolbutton);
	builder->get_widget("stop_toolbutton"   , stop_toolbutton);
	builder->get_widget("restart_toolbutton", restart_toolbutton);
	builder->get_widget("open_toolbutton"   , open_toolbutton);
	builder->get_widget("save_toolbutton"   , save_toolbutton);
	builder->get_widget("close_toolbutton"  , close_toolbutton);

	builder->get_widget("alldevs_listbox", alldevs_listbox);
	builder->get_widget("ltreeview", ltreeview);
	builder->get_widget("ttreeview", ttreeview);
	builder->get_widget("btextview", btextview);

}

void ui_callback_setup()
{
	open_menuitem->signal_activate().connect(ptr_fun(on_open_clicked));
	close_menuitem->signal_activate().connect(ptr_fun(on_close_clicked));
	save_menuitem->signal_activate().connect(ptr_fun(on_save_clicked));
	quit_menuitem->signal_activate().connect([]{app->quit();});
	start_menuitem->signal_activate().connect(ptr_fun(on_start_clicked));
	stop_menuitem->signal_activate().connect(ptr_fun(on_stop_clicked));
	restart_menuitem->signal_activate().connect(ptr_fun(on_restart_clicked));
	about_menuitem->signal_activate().connect(ptr_fun(on_about_clicked));

	start_toolbutton->signal_clicked().connect(ptr_fun(on_start_clicked));
	stop_toolbutton->signal_clicked().connect(ptr_fun(on_stop_clicked));
	restart_toolbutton->signal_clicked().connect(ptr_fun(on_restart_clicked));
	open_toolbutton->signal_clicked().connect(ptr_fun(on_open_clicked));
	save_toolbutton->signal_clicked().connect(ptr_fun(on_save_clicked));
	close_toolbutton->signal_clicked().connect(ptr_fun(on_close_clicked));

	alldevs_listbox->signal_row_selected().connect([](ListBoxRow* r) {
		start_menuitem->set_sensitive(r != NULL);
		start_toolbutton->set_sensitive(r != NULL);
	});

	ltreeview->get_selection()->signal_changed().connect(ptr_fun(on_row_selected));
	ltreeview->show_all_children();
}

void ui_setup()
{
	toolbutton_setup(start_toolbutton, start_icon, start_icon_size);
	toolbutton_setup(stop_toolbutton, stop_icon, stop_icon_size);
	toolbutton_setup(restart_toolbutton, restart_icon, restart_icon_size);
	toolbutton_setup(open_toolbutton, open_icon, open_icon_size);
	toolbutton_setup(save_toolbutton, save_icon, save_icon_size);
	toolbutton_setup(close_toolbutton, close_icon, close_icon_size);

	RefPtr<PixbufLoader> loader;
	icon_pixbuf = get_pixbuf_from_icon(loader, icon, icon_size);
	main_application_window->set_icon(icon_pixbuf);
	error_icon_image = new Image(get_pixbuf_from_icon(loader, error_icon, error_icon_size));
}

void setup()
{
	lmodel = lcol.create_and_set(ltreeview);
	tmodel = tcol.create_and_set(ttreeview);

	find_update_alldevs();
	update_alldevs = signal_timeout().connect_seconds([]{
		find_update_alldevs();
		return true;
	}, UPDATE_ALLDEVS_INTERVAL);

	dispatcher.connect(ptr_fun(update_packets));
}

void on_open_clicked()
{
	FileChooserDialog dialog(*main_application_window, "Open Capture File", FILE_CHOOSER_ACTION_OPEN);
    dialog.add_button("Cancel", RESPONSE_CANCEL);
    dialog.add_button("Select", RESPONSE_OK);
	RefPtr<FileFilter> ff = FileFilter::create();
	ff->add_pattern("*.pcap");
	dialog.set_filter(ff);
	if(dialog.run() != RESPONSE_OK) return;

	pcap_t *handle = pcap_open_offline(dialog.get_filename().c_str(), errbuf);
	if(handle == NULL) {
		show_error_message(errbuf);
		return;
	}

	if(int dlt = pcap_datalink(handle); dlt != DLT_EN10MB) {
		pcap_close(handle);
		show_error_message(string(pcap_datalink_val_to_name(dlt)) + " link layer is not supported");
		return;
	}

	if(pd != NULL) {
		pcap_dump_close(pd);
		pd = NULL;
	}

	start_menuitem->set_sensitive(false);
	start_toolbutton->set_sensitive(false);
	open_menuitem->set_sensitive(false);
	open_toolbutton->set_sensitive(false);
	save_menuitem->set_sensitive(false);
	save_toolbutton->set_sensitive(false);

	if(!close_toolbutton->get_sensitive()) {
		update_alldevs.disconnect();
		stack_window->set_visible_child(*page2);
	} else {
		close_menuitem->set_sensitive(false);
		close_toolbutton->set_sensitive(false);
		on_close_cleanup();
	}

	eth_packet_t p;
	struct ud u = { &npackets, &p, NULL, NULL };
	memset(&p, 0, sizeof(p));
	while(pcap_dispatch(handle, 1, process_packet, (uint8_t *) &u) > 0) {
		dqpackets.push_back(p);
		if(p.no == 1) ts = p.ts;
		TreeModel::Row row = *(lmodel->append());
		row[lcol.no]    = p.no;
		row[lcol.ts]    = tdiff(p.ts, ts);
		row[lcol.src]   = (p.net.type == TYPE_IP) ? ip_hstoa(p.net.raw): ether_hstoa(&p.eth);
		row[lcol.dest]  = (p.net.type == TYPE_IP) ? ip_hdtoa(p.net.raw): ether_hdtoa(&p.eth);
		row[lcol.proto] = get_protocol(&p);
		row[lcol.len]   = p.len;

		memset(&p, 0, sizeof(p));
	}
	pcap_close(handle);

	find_update_alldevs();
	ListBoxRow *r = alldevs_listbox->get_selected_row();
	start_menuitem->set_sensitive(r != NULL);
	start_toolbutton->set_sensitive(r != NULL);
	open_menuitem->set_sensitive(true);
	open_toolbutton->set_sensitive(true);
	save_menuitem->set_sensitive(false);
	save_toolbutton->set_sensitive(false);
	close_menuitem->set_sensitive(true);
	close_toolbutton->set_sensitive(true);
}

void on_close_cleanup()
{
	npackets = 0;
	lmodel->clear();
	tmodel->clear();
	btextview->get_buffer()->set_text(string(""));
	for_each(dqpackets.begin(), dqpackets.end(), [](eth_packet_t &e) {
		free_packet(&e);
	});
	dqpackets.clear();
}

void on_close_clicked()
{
	if(pd != NULL) {
		pcap_dump_close(pd);
		pd = NULL;
	}

	close_menuitem->set_sensitive(false);
	close_toolbutton->set_sensitive(false);
	save_menuitem->set_sensitive(false);
	save_toolbutton->set_sensitive(false);
	stop_menuitem->set_sensitive(false);
	stop_toolbutton->set_sensitive(false);
	restart_menuitem->set_sensitive(false);
	restart_toolbutton->set_sensitive(false);

	find_update_alldevs();
	ListBoxRow *r = alldevs_listbox->get_selected_row();
	stack_window->set_visible_child(*page1);

	update_alldevs = signal_timeout().connect_seconds([]{
			find_update_alldevs();
			return true;
	}, UPDATE_ALLDEVS_INTERVAL);

	start_menuitem->set_sensitive(r != NULL);
	start_toolbutton->set_sensitive(r != NULL);
	open_menuitem->set_sensitive(true);
	open_toolbutton->set_sensitive(true);

	on_close_cleanup();
}

void on_save_clicked()
{
	FileChooserDialog dialog(*main_application_window, "", FILE_CHOOSER_ACTION_SAVE);
    dialog.add_button("Cancel", RESPONSE_CANCEL);
    dialog.add_button("Save", RESPONSE_OK);
	dialog.set_do_overwrite_confirmation();
	if(dialog.run() != RESPONSE_OK) return;

	save_menuitem->set_sensitive(false);
	save_toolbutton->set_sensitive(false);

	FILE *fp = fopen(dialog.get_filename().c_str(), "wb");
	FILE *ft = pcap_dump_file(pd);
	long sz = ftell(ft);
	void *p = malloc(sz);
	fseek(ft, 0, SEEK_SET);
	fread(p, sz, 1, ft);
	fwrite(p, sz, 1, fp);
	fclose(fp);
	pcap_dump_close(pd);
	free(p);
	pd = NULL;
}

void on_start_clicked()
{
	if(pd != NULL) {
		pcap_dump_close(pd);
		pd = NULL;
	}

	start_menuitem->set_sensitive(false);
	start_toolbutton->set_sensitive(false);
	open_menuitem->set_sensitive(false);
	open_toolbutton->set_sensitive(false);
	save_menuitem->set_sensitive(false);
	save_toolbutton->set_sensitive(false);

	if(!close_toolbutton->get_sensitive()) {
		update_alldevs.disconnect();
		stack_window->set_visible_child(*page2);
	} else {
		close_menuitem->set_sensitive(false);
		close_toolbutton->set_sensitive(false);
		on_close_cleanup();
	}

	if(start_sniff(c_str_from_selected_row(alldevs_listbox)) < 0) return;

	stop_menuitem->set_sensitive(true);
	stop_toolbutton->set_sensitive(true);
	restart_menuitem->set_sensitive(true);
	restart_toolbutton->set_sensitive(true);
}

void on_stop_clicked()
{
	stop_menuitem->set_sensitive(false);
	stop_toolbutton->set_sensitive(false);
	restart_menuitem->set_sensitive(false);
	restart_toolbutton->set_sensitive(false);

	pcap_breakloop(handle);
	sniff_thread->join();
	delete sniff_thread;

	start_menuitem->set_sensitive(true);
	start_toolbutton->set_sensitive(true);
	open_menuitem->set_sensitive(true);
	open_toolbutton->set_sensitive(true);
	save_menuitem->set_sensitive(npackets);
	save_toolbutton->set_sensitive(npackets);
	close_menuitem->set_sensitive(true);
	close_toolbutton->set_sensitive(true);
}

void on_restart_clicked()
{
	stop_menuitem->set_sensitive(false);
	stop_toolbutton->set_sensitive(false);
	restart_menuitem->set_sensitive(false);
	restart_toolbutton->set_sensitive(false);

	pcap_breakloop(handle);
	sniff_thread->join();
	delete sniff_thread;

	on_close_cleanup();

	if(start_sniff(c_str_from_selected_row(alldevs_listbox)) < 0) return;

	stop_menuitem->set_sensitive(true);
	stop_toolbutton->set_sensitive(true);
	restart_menuitem->set_sensitive(true);
	restart_toolbutton->set_sensitive(true);
}

void on_about_clicked()
{
	AboutDialog dialog;
	dialog.set_program_name("El Mashro3");
	dialog.set_version("0.1");
	dialog.set_comments("A Wireshark Replica");
	dialog.set_logo(icon_pixbuf);
	dialog.set_transient_for(*main_application_window);
	dialog.run();
}

void on_row_selected()
{
	TreeModel::iterator it = ltreeview->get_selection()->get_selected();
	if(!it) return;
	eth_packet_t p = dqpackets[(*it)[lcol.no] - 1];

	uint32_t len = 0;
	char *const s = (char *) malloc(4*p.len);
	char *a = s;

	for(int16_t i = 0; len < p.len && i < ETHER_HLEN; ++len, ++i, a += 3) {
		if(!(len & 31)) *a++ = '\n';
		sprintf(a, "%02hhX ", p.eth_raw[i]);
	}
	for(int16_t i = 0; len < p.len && i < p.net.sz; ++len, ++i, a += 3) {
		if(!(len & 31)) *a++ = '\n';
		sprintf(a, "%02hhX ", p.net.raw[i]);
	}
	for(int16_t i = 0; len < p.len && i < p.trans.sz; ++len, ++i, a += 3) {
		if(!(len & 31)) *a++ = '\n';
		sprintf(a, "%02hhX ", p.trans.raw[i]);
	}
	for(int16_t i = 0; len < p.len && i < p.app.sz; ++len, ++i, a += 3) {
		if(!(len & 31)) *a++ = '\n';
		sprintf(a, "%02hhX ", p.app.raw[i]);
	}

	btextview->get_buffer()->set_text(s, a);
	free(s);
}

void show_error_message(string msg)
{
	MessageDialog *md = new MessageDialog (
		*main_application_window,
		msg,
		false,
		MESSAGE_ERROR,
		BUTTONS_OK,
		true
	);

	md->signal_response().connect([md](int rid) {
		if(rid == RESPONSE_OK) {
			md->close();
			delete md;
		}
	});

	md->set_image(*error_icon_image);
	error_icon_image->show();
	md->show();
}

int find_update_alldevs()
{
	typedef struct is {
		size_t i;
		string s;
	} is_t;

	size_t j = 0;
	size_t k = 0;
	pcap_if_t *dev;
	pcap_if_t *alldevs;
	vector<struct is> isn;
	vector<struct is> iso;
	vector<struct is> isd;
	vector<struct is>::iterator isdit;

	if(pcap_findalldevs(&alldevs, errbuf) == -1) return -1;
	for(dev = alldevs; dev != NULL; dev = dev->next) ++j;
	for(isn.reserve(j), dev = alldevs; k < j; dev = dev->next)
		isn.push_back(is_t{ k++, dev->name });
	pcap_freealldevs(alldevs);

	vector<Widget*> v = alldevs_listbox->get_children();
	k = 0;
	iso.reserve(v.size());
	for_each(v.begin(), v.end(), [&k, &iso](Widget *w) {
		iso.push_back(is_t{ k++, label_from_listboxrow((ListBoxRow *) w) });
	});

	bool (*cmpiss)(struct is, struct is) = [](struct is isa, struct is isb) {
		return isa.s.compare(isb.s) < 0;
	};

	sort(iso.begin(), iso.end(), cmpiss);
	sort(isn.begin(), isn.end(), cmpiss);

	isd.resize(iso.size());
	isdit = set_difference(iso.begin(), iso.end(), isn.begin(), isn.end(), isd.begin(), cmpiss);
	isd.resize(isdit-isd.begin());

	for_each(isd.begin(), isd.end(), [v](struct is &ise) {
		Widget *w = v[ise.i];
		delete ((ListBoxRow *) w)->get_child();
		delete w;
	});

	isd.clear();
	isd.resize(isn.size());
	isdit = set_difference(isn.begin(), isn.end(), iso.begin(), iso.end(), isd.begin(), cmpiss);
	isd.resize(isdit-isd.begin());

	sort(isd.begin(), isd.end(), [](struct is isa, struct is isb) {
		return isa.i < isb.i;
	});

	for_each(isd.begin(), isd.end(), [](struct is &ise) {
		ListBoxRow *r = new ListBoxRow();
		Label *l = new Label(ise.s, Align::ALIGN_START);
		r->add(*l);
		alldevs_listbox->insert(*r, ise.i);
		r->show();
		l->show();
	});

	return 0;
}

int start_sniff(const char *const dev)
{
	handle = pcap_create(dev, errbuf);
	pcap_set_snaplen(handle, SNAPLEN);
	pcap_set_promisc(handle, 1);

	if(int status = pcap_activate(handle); status < 0) {
		pcap_close(handle);
		show_error_message(get_error_string(dev, status, handle));
		on_close_clicked();
		return -1;
	}

	if(int dlt = pcap_datalink(handle); dlt != DLT_EN10MB) {
		pcap_close(handle);
		show_error_message(string(pcap_datalink_val_to_name(dlt)) + " link layer is not supported");
		on_close_clicked();
		return -1;
	}

	pcap_setnonblock(handle, 1, errbuf);

	qpackets = new boost::sync_queue<eth_packet_t>();
	pd       = pcap_dump_fopen(handle, tmpfile());

	sniff_thread = new thread([] {
		int s;
		eth_packet_t p;
		struct ud u = { &npackets, &p, pcap_dump, (uint8_t *) pd };
		memset(&p, 0, sizeof(p));
		while((s = pcap_dispatch(handle, 1, process_packet, (uint8_t *) &u)) >= 0)
			if(s) {
				qpackets->push(p);
				dispatcher.emit();
				memset(&p, 0, sizeof(p));
			}
		qpackets->close();
		pcap_close(handle);
	});

	return 0;
}

void update_packets()
{
	eth_packet_t p;
	qpackets->pull(p);
	dqpackets.push_back(p);

	if(p.no == 1) ts = p.ts;

	TreeModel::Row row = *(lmodel->append());
	row[lcol.no]    = p.no;
	row[lcol.ts]    = tdiff(p.ts, ts);
	row[lcol.src]   = (p.net.type == TYPE_IP) ? ip_hstoa(p.net.raw): ether_hstoa(&p.eth);
	row[lcol.dest]  = (p.net.type == TYPE_IP) ? ip_hdtoa(p.net.raw): ether_hdtoa(&p.eth);
	row[lcol.proto] = get_protocol(&p);
	row[lcol.len]   = p.len;
}
