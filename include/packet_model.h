#ifndef PACKET_MODEL_H
#define PACKET_MODEL_H

#include <string>
#include <cstdint>
#include <gtkmm.h>

class ListModelColumns : public Gtk::TreeModelColumnRecord
{
public:
	ListModelColumns()
	{
		add(no); add(ts); add(src); add(dest); add(proto); add(len);
	}

    Glib::RefPtr<Gtk::ListStore> create_and_set(Gtk::TreeView *view)
    {
        Glib::RefPtr<Gtk::ListStore> model = Gtk::ListStore::create(*this);
        view->set_model(model);
        view->append_column("No."        , no);
        view->append_column("Time"       , ts);
        view->append_column("Source"     , src);
        view->append_column("Destination", dest);
        view->append_column("Protocol"   , proto);
        view->append_column("Length     ", len);
        return model;
    }

	Gtk::TreeModelColumn<size_t> no;
	Gtk::TreeModelColumn<float> ts;
	Gtk::TreeModelColumn<std::string> src;
	Gtk::TreeModelColumn<std::string> dest;
	Gtk::TreeModelColumn<std::string> proto;
	Gtk::TreeModelColumn<uint32_t> len;
};

class TreeModelColumns : public Gtk::TreeModelColumnRecord
{
public:
	TreeModelColumns()
	{
		add(str);
	}

    Glib::RefPtr<Gtk::TreeStore> create_and_set(Gtk::TreeView *view)
    {
        Glib::RefPtr<Gtk::TreeStore> model = Gtk::TreeStore::create(*this);
        view->set_model(model);
        view->append_column("", str);
        return model;
    }

	Gtk::TreeModelColumn<std::string> str;
};

#endif
