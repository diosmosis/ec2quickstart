#!/usr/bin/env python

# TODO: document
# TODO: argument checking
# TODO: make prettier
# TODO: test resnapshotting function
# TODO: ProgressWindow's progress text must be set before invoking the associated operation so
#     it is displayed while the operation is executing. This has to be done by execute_operation_step
#     rather than OperationStep.

import time
import pygtk
pygtk.require('2.0')
import gtk
import subprocess
import os
import urllib2
import sys
import pickle
import copy
import gobject
import inspect
import paramiko

from boto.ec2 import connection, image, volume, securitygroup, keypair

# constants
GET_IP_FAILURE_THRESHOLD = 5
CONNECT_SSH_FAILURE_THRESHOLD = -1
DETACHED_PROCESS = 0x00000008
TEMP_SECURITY_GROUP_NAME = 'qstempsg'
CONFIG_FILE_NAME = 'ec2quickstart.config'

def display_error_msg(parent, message):
  # create and run the message window
  msg_win = gtk.MessageDialog(parent, gtk.DIALOG_MODAL, gtk.MESSAGE_ERROR, gtk.BUTTONS_OK, message)

  msg_win.set_title('Error')
  msg_win.run()

  # destroy the message window
  msg_win.destroy()

def display_info_msg(parent, message):
  msg_win = gtk.MessageDialog(parent, gtk.DIALOG_MODAL, gtk.MESSAGE_INFO, gtk.BUTTONS_OK, message)
  msg_win.run()
  msg_win.destroy()

def ask_yes_no(parent, message):
  # create and run the message window
  msg_win = gtk.MessageDialog(parent, gtk.DIALOG_MODAL, gtk.MESSAGE_QUESTION, gtk.BUTTONS_YES_NO, message)
  response = msg_win.run()

  # destroy the message window now that its not needed
  msg_win.destroy()

  # return true if the response was 'Yes'
  return response == gtk.RESPONSE_YES

def alternate_image_name(name):
  if name[len(name) - 1] == '2':
    return name[0:len(name) - 1]
  else:
    return name + '2'

class PickAMIDialog(gtk.Dialog):

  def __init__(self, parent, conn, image_ids):
    gtk.Dialog.__init__(self, 'Pick an AMI...', parent, gtk.DIALOG_MODAL, \
      (gtk.STOCK_OK, gtk.RESPONSE_OK, gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL))

    # init private members
    self._conn = conn

    # get images
    self._images = conn.get_all_images(image_ids)

    # create widgets
    self._label = gtk.Label('AMI:')
    self._combo_box = gtk.combo_box_new_text()
    for x in self._images:
      self._combo_box.append_text(x.name)
    self._hbox = gtk.HBox(spacing = 10)

    self._hbox.pack_start(self._label)
    self._hbox.pack_start(self._combo_box)

    # pack widgets
    self.vbox.pack_start(self._hbox)

    self.vbox.show_all()

  def run_and_return(self):
    response = self.run()

    ami = None
    if response == gtk.RESPONSE_OK:
      result = self._combo_box.get_active()
      if result != -1:
        ami = self._images[result]

    self.destroy()

    return ami

class ProgressDialog(gtk.Dialog):

  def __init__(self, parent, total_steps):
    gtk.Dialog.__init__(self, 'Progress', parent, gtk.DIALOG_MODAL, \
      (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL, gtk.STOCK_OK, gtk.RESPONSE_OK))

    # init members
    self._total_steps = float(total_steps)
    self._current_step = -1.0
    self._can_destroy = False
    self.is_cancelled = False

    # get the buttons before any other buttons are added
    self._cancel_button = self.get_action_area().get_children()[1]
    self._ok_button = self.get_action_area().get_children()[0]

    # create widgets
    self._bar = gtk.ProgressBar()
    self._log = gtk.TextView()
    self._log.set_editable(False)
    self._log.set_cursor_visible(False)
    self._log.set_wrap_mode(gtk.WRAP_WORD)
    self._sw = gtk.ScrolledWindow()
    self._sw.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
    self._sw.add(self._log)

    # pack widgets
    self.vbox.props.spacing = 10
    self.vbox.pack_start(self._bar, expand=False)
    self.vbox.pack_start(self._sw)

    # connect widgets
    self.connect('delete_event', self.on_destroy)
    self.connect('response', self.on_response)

    # disable ok button
    self._ok_button.props.sensitive = False

    self.resize(600, 400)

    self.show_all()

  def on_response(self, widget, response_id):
    if response_id == gtk.RESPONSE_CANCEL:
      self.is_cancelled = True
    elif response_id == gtk.RESPONSE_OK:
      self.destroy()

  def some_progress_made(self, msg=None):
    self._bar.set_fraction(self._bar.get_fraction() + (1 / self._total_steps / 20))
    if msg:
      self._bar.set_text(msg)

  def progress_made(self, msg):
    self._current_step = self._current_step + 1
    self._bar.set_fraction(self._current_step / self._total_steps)
    self._bar.set_text(msg)

  def on_destroy(self, widget, evt):
    return not self._can_destroy

  def failed(self):
    self._bar.set_text('FAILED')
    self._can_destroy = True
    self._cancel_button.props.sensitive = False
    self._ok_button.props.sensitive = True

  def done(self):
    self._bar.set_text('DONE')
    self._bar.set_fraction(1.0)
    self._can_destroy = True
    self._cancel_button.props.sensitive = False
    self._ok_button.props.sensitive = True

  # called after an operation is rolled back
  def cancelled(self):
    self._bar.set_text('CANCELLED')
    self._can_destroy = True
    self._cancel_button.props.sensitive = False
    self._ok_button.props.sensitive = True

  def log(self, msg):
    buf = self._log.get_buffer()
    buf.insert(buf.get_end_iter(), msg + '\n')
    self.scroll_to_end()

  def replace_last_log(self, msg):
    buf = self._log.get_buffer()
    line_start = buf.get_end_iter()
    line_start.backward_visible_line()
    end_iter = buf.get_end_iter()
    buf.delete(line_start, end_iter)
    buf.insert(end_iter, msg + '\n')
    self.scroll_to_end()

  def scroll_to_end(self):
    self._log.scroll_to_mark(self._log.get_buffer().get_mark('insert'), 0.0)

class SecurityGroupRule():

  # TODO: Should be able to allow any IP address instead of everyone/all
  IP_ALL = 0
  IP_ME = 1

  PROTOCOL_TCP = 0
  PROTOCOL_UDP = 1

  def __init__(self, port_from = 0, port_to = 0, protocol = PROTOCOL_TCP, ip = IP_ME):
    # init private members
    self.port_from = port_from
    self.port_to = port_to
    self.protocol = protocol
    self.ip = ip

class Config():

  def __init__(self):
    # init private members
    self.ec2qs_id = None
    self.ec2qs_pass = None
    self.extra_volume_id = None
    self.keypair_name = None
    self.ssh_passwords = {}
    self.ssh_usernames = {}
    self.security_rules = [
      # SSH
      SecurityGroupRule(22, 22, SecurityGroupRule.PROTOCOL_TCP, SecurityGroupRule.IP_ME),

      # RDP
      SecurityGroupRule(3389, 3389, SecurityGroupRule.PROTOCOL_TCP, SecurityGroupRule.IP_ME),

      # HTTP
      SecurityGroupRule(80, 80, SecurityGroupRule.PROTOCOL_TCP, SecurityGroupRule.IP_ALL)
    ]

class SecurityRuleWidget(gtk.HBox):

  def __init__(self, rule, on_delete):
    gtk.HBox.__init__(self)

    self.set_spacing(10)

    # init private members
    self.rule = rule

    # create widgets
    self._port_from_lbl = gtk.Label('From Port')
    self._port_from_entry = gtk.Entry()
    self._port_from_entry.set_width_chars(7)
    self._port_to_lbl = gtk.Label('To Port')
    self._port_to_entry = gtk.Entry()
    self._port_to_entry.set_width_chars(7)
    self._protocol_lbl = gtk.Label('Protocol')
    self._protocol_combo = gtk.combo_box_new_text()
    self._ip_lbl = gtk.Label('Allowed IPs')
    self._ip_combo = gtk.combo_box_new_text()
    self._delete_button = gtk.Button('Delete')

    # fill combo boxes
    self._protocol_combo.append_text('tcp')
    self._protocol_combo.append_text('udp')

    self._ip_combo.append_text('Everyone')
    self._ip_combo.append_text('Me')

    # connect widgets
    self._port_from_entry.connect('changed', self.port_from_changed)
    self._port_from_entry.connect('insert-text', self.disallow_alpha)
    self._port_to_entry.connect('changed', self.port_to_changed)
    self._port_to_entry.connect('insert-text', self.disallow_alpha)
    self._protocol_combo.connect('changed', self.protocol_changed)
    self._ip_combo.connect('changed', self.ip_changed)
    self._delete_button.connect('clicked', lambda (w): on_delete(self))

    # initialize widgets
    self._port_from_entry.props.text = str(rule.port_from)
    self._port_to_entry.props.text = str(rule.port_to)
    self._protocol_combo.set_active(rule.protocol)
    self._ip_combo.set_active(rule.ip)

    # add widgets
    self.pack_start(self._port_from_lbl, expand=False, fill=False)
    self.pack_start(self._port_from_entry, expand=True, fill=False)
    self.pack_start(self._port_to_lbl, expand=False, fill=False)
    self.pack_start(self._port_to_entry, expand=True, fill=False)
    self.pack_start(self._protocol_lbl, expand=False, fill=False)
    self.pack_start(self._protocol_combo, expand=True, fill=False)
    self.pack_start(self._ip_lbl, expand=False, fill=False)
    self.pack_start(self._ip_combo, expand=True, fill=False)

  def disallow_alpha(self, widget, text, length, pos):
    can_insert = True
    for c in text:
      if c < '0' or c > '9':
        can_insert = False

    if not can_insert:
      widget.stop_emission('insert-text')

  def port_from_changed(self, widget):
    if self._port_from_entry.props.text == '':
      self.rule.port_from = 0
    else:
      self.rule.port_from = int(self._port_from_entry.props.text)

  def port_to_changed(self, widget):
    if self._port_to_entry.props.text == '':
      self.rule.port_to = 0
    else:
      self.rule.port_to = int(self._port_to_entry.props.text)

  def protocol_changed(self, widget):
    self.rule.protocol = self._protocol_combo.get_active()

  def ip_changed(self, widget):
    self.rule.ip = self._ip_combo.get_active()

class ConfigSecurityGroupDialog(gtk.Dialog):

  def __init__(self, parent, app, rules):
    gtk.Dialog.__init__(self, 'Configure Temporary Security Group', parent, gtk.DIALOG_MODAL, \
      (gtk.STOCK_OK, gtk.RESPONSE_OK, gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL))

    # init public members
    self.rules = copy.deepcopy(rules)

    # init private members
    self._app = app

    # create rule widgets
    self._rule_widgets_lbl = gtk.Label('Security Rules:')
    self._rule_widgets = [SecurityRuleWidget(x, self.delete_rule) for x in self.rules]

    # create other widgets
    self._add_button = gtk.Button('Add')
    self.get_action_area().pack_start(self._add_button, expand=False, fill=False)

    # connect widgets
    self._add_button.connect('clicked', self.add_rule)

    # add widgets
    for w in self._rule_widgets:
      self.vbox.pack_start(w, expand=True, fill=True)

    self.show_all()

  def add_rule(self, widget):
    new_rule = SecurityGroupRule()
    self.rules.append(new_rule)

    new_rule_widget = SecurityRuleWidget(new_rule, self.delete_rule)
    self._rule_widgets.append(new_rule_widget)
    self.vbox.pack_start(new_rule_widget, expand=True, fill=True)
    self.vbox.show_all()

  def delete_rule(self, widget):
    self.rules.remove(widget.rule)
    self.vbox.remove(widget)
    self._rule_widgets.remove(widget)

  def run_and_return(self):
    response = self.run()

    if response != gtk.RESPONSE_OK:
      return None

    return self.rules

class ConfigDialog(gtk.Dialog):

  def __init__(self, app, config):
    gtk.Dialog.__init__(self, 'Edit Configuration', app.window, gtk.DIALOG_MODAL, \
      (gtk.STOCK_OK, gtk.RESPONSE_OK, gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL))

    # init private members
    self._app = app
    self._config = config
    self._images = None
    self._volumes = None
    self._keypairs = None
    self._ssh_passwords = copy.copy(config.ssh_passwords)
    self._ssh_usernames = copy.copy(config.ssh_usernames)

    # create widgets for EC2 login info
    self._login_frame = gtk.Frame('EC2 Login Info')
    self._login_frame.set_shadow_type(gtk.SHADOW_ETCHED_IN)

    login_hbox = gtk.HBox()
    self._login_id_label = gtk.Label('ID:')
    self._login_id = gtk.Entry()
    self._login_id.set_width_chars(25)
    self._login_pass_label = gtk.Label('Password:')
    self._login_pass = gtk.Entry()
    self._login_pass.set_width_chars(25)
    self._login_btn = gtk.Button('Login')
    login_hbox.pack_start(self._login_id_label)
    login_hbox.pack_start(self._login_id, padding=5)
    login_hbox.pack_start(self._login_pass_label, padding=10)
    login_hbox.pack_start(self._login_pass, padding=5)
    login_hbox.pack_start(self._login_btn, padding=10)
    self._login_frame.add(login_hbox)

    # create widgets for AMI agnostic info
    extra_volume_hbox = gtk.HBox()
    self._extra_volume_label = gtk.Label('Extra Volume:')
    self._extra_volume = gtk.combo_box_new_text()
    extra_volume_hbox.pack_start(self._extra_volume_label)
    extra_volume_hbox.pack_start(self._extra_volume, padding=5)

    keypair_hbox = gtk.HBox()
    self._keypair_label = gtk.Label('Keypair:')
    self._keypair_combo = gtk.combo_box_new_text()
    keypair_hbox.pack_start(self._keypair_label)
    keypair_hbox.pack_start(self._keypair_combo, padding=5)

    # create widgets for AMI specific info
    self._ami_details_frame = gtk.Frame('AMI Details')
    self._ami_details_frame.set_shadow_type(gtk.SHADOW_ETCHED_IN)

    ami_hbox = gtk.HBox()
    self._ami_label = gtk.Label('AMI:')
    self._ami_combo = gtk.combo_box_new_text()
    ami_hbox.pack_start(self._ami_label)
    ami_hbox.pack_start(self._ami_combo, padding=5)

    ami_details_hbox = gtk.HBox()
    self._ssh_user_label = gtk.Label('SSH Username:')
    self._ssh_user = gtk.Entry()
    self._ssh_user.set_width_chars(25)
    self._ssh_user.props.sensitive = False
    self._ssh_password_label = gtk.Label('SSH Password:')
    self._ssh_password = gtk.Entry()
    self._ssh_password.set_width_chars(25)
    self._ssh_password.props.sensitive = False
    ami_details_hbox.pack_start(self._ssh_user_label)
    ami_details_hbox.pack_start(self._ssh_user, padding=5)
    ami_details_hbox.pack_start(self._ssh_password_label, padding=10)
    ami_details_hbox.pack_start(self._ssh_password, padding=5)
    
    ami_details_vbox = gtk.VBox()
    ami_details_vbox.pack_start(ami_hbox, padding=3)
    ami_details_vbox.pack_start(ami_details_hbox, padding=3)

    self._ami_details_frame.add(ami_details_vbox)

    # add to the dialog's vbox
    self.vbox.pack_start(self._login_frame, padding=3)
    self.vbox.pack_start(extra_volume_hbox, padding=3)
    self.vbox.pack_start(keypair_hbox, padding=3)
    self.vbox.pack_start(self._ami_details_frame, padding=3)

    # create security rules modification button
    self._modify_rules = gtk.Button('Modify Security Rules')
    self.get_action_area().pack_start(self._modify_rules, expand=False, fill=False)

    # add event handlers
    self._login_id.connect('changed', self.login_info_changed)
    self._login_pass.connect('changed', self.login_info_changed)
    self._login_btn.connect('clicked', self.login_btn_clicked, True)
    self._ami_combo.connect('changed', self.ami_selection_changed)
    self._ssh_user.connect('changed', self.ssh_user_changed)
    self._ssh_password.connect('changed', self.ssh_password_changed)
    self._modify_rules.connect('clicked', self.modify_security_rules)

    # populate entries (if possible)
    if self._config.ec2qs_id:
      self._login_id.set_text(self._config.ec2qs_id)
    if self._config.ec2qs_pass:
      self._login_pass.set_text(self._config.ec2qs_pass)

    self.login_btn_clicked(self, False)

    self.show_all()

  def set_all_sensitive(self, sensitive):
    self._extra_volume.set_sensitive(sensitive)
    self._keypair_combo.set_sensitive(sensitive)
    self._ami_combo.set_sensitive(sensitive)

  def login_info_changed(self, widget):
    self.set_all_sensitive(False)
    if self._app._connection:
      self._app._connection = None

  def modify_security_rules(self, widget):
    dlog = ConfigSecurityGroupDialog(self, self._app, self._config.security_rules)

    rules = dlog.run_and_return()

    dlog.destroy()

    if rules:
      self._config.security_rules = rules

  def login_btn_clicked(self, widget, display_error=True):
    # try and login to AWS
    conn = self.get_connection()

    # if login fails, display an error and abort
    if conn == None:
      self.set_all_sensitive(False)
      if display_error:
        display_error_msg(self, 'Unable to login.')
      return

    # populate combos
    self.populate_volume_combo()
    self.populate_ami_combo()
    self.populate_keypair_combo()

    # enable non-login controls
    self.set_all_sensitive(True)

  def ami_selection_changed(self, widget):
    selected_ami_n = self._ami_combo.get_active()

    if selected_ami_n == -1:
      self._ssh_user.set_text('')
      self._ssh_user.set_sensitive(False)
      self._ssh_password.set_text('')
      self._ssh_password.set_sensitive(False)
    else:
      self._ssh_user.props.sensitive = True
      self._ssh_password.props.sensitive = True

      selected_ami_id = self._images[selected_ami_n].id

      if selected_ami_id in self._ssh_usernames:
        self._ssh_user.set_text(self._ssh_usernames[selected_ami_id])
        self._ssh_password.set_text(self._ssh_passwords[selected_ami_id])
      else:
        self._ssh_user.props.text = ''
        self._ssh_password.props.text = ''

  def ssh_user_changed(self, widget):
    selected_ami_n = self._ami_combo.get_active()

    if selected_ami_n == -1:
      return

    selected_ami_id = self._images[selected_ami_n].id
    self._ssh_usernames[selected_ami_id] = self._ssh_user.get_text()

  def ssh_password_changed(self, widget):
    selected_ami_n = self._ami_combo.get_active()

    if selected_ami_n == -1:
      return

    selected_ami_id = self._images[selected_ami_n].id
    self._ssh_passwords[selected_ami_id] = self._ssh_password.get_text()

  def get_connection(self):
    # if the connection has already been made, return it
    if self._app._connection:
      return self._app._connection

    # if the id & password have been set, try and connect
    if self._login_id.get_text() and self._login_pass.get_text():
      try:
        self._app._connection = connection.EC2Connection( \
          self._login_id.get_text(), self._login_pass.get_text())
        return self._app._connection
      except:
        pass

    # can't make a connection, return None
    return None
  
  def populate_volume_combo(self):
    conn = self.get_connection()

    if conn == None:
      return

    # get the selected volume, if any
    selected_volume_id = self._config.extra_volume_id
    if self._extra_volume.get_active() != -1 and self._volumes:
      selected_volume_id = self._volumes[self._extra_volume.get_active()].id

    # get all volumes & populate the volume ListStore
    self._volumes = conn.get_all_volumes()
    self._extra_volume.set_active(-1)
    self._extra_volume.get_model().clear()
    for x in self._volumes:
      self._extra_volume.append_text(x.id)

    # if the extra volume is specified in self._config, set the active volume
    if selected_volume_id:
      for i in range(0, len(self._volumes)):
        if self._volumes[i].id == selected_volume_id:
          self._extra_volume.set_active(i)
          break

  def populate_ami_combo(self):
    conn = self.get_connection()

    if conn == None:
      return

    # get the selected AMI, if any
    selected_ami_id = None
    if self._ami_combo.get_active() != -1 and self._images:
      selected_ami_id = self._images[self._ami_combo.get_active()].id

    # get all images & populate the image ListStore
    self._images = [x for x in conn.get_all_images(owners = ['self']) if x.name != None and not x.is_public]
    self._ami_combo.set_active(-1)
    self._ami_combo.get_model().clear()
    for x in self._images:
      self._ami_combo.append_text(x.name)

    # if an AMI was selected, re-select it
    if selected_ami_id:
      for i in range(0, len(self._images)):
        if self._images[i].id == selected_ami_id:
          self._ami_combo.set_active(i)
          break
    else:
      self._ami_combo.set_active(0)

  def populate_keypair_combo(self):
    conn = self.get_connection()

    if conn == None:
      return

    # get the selected keypair, if any
    selected_keypair = self._config.keypair_name
    if self._keypair_combo.get_active() != -1 and self._keypairs:
      selected_keypair = self._keypairs[self._keypair_combo.get_active()].name

    # get all keypairs & populate the keypair ListStore
    self._keypairs = conn.get_all_key_pairs()
    self._keypair_combo.set_active(-1)
    self._keypair_combo.get_model().clear()
    for x in self._keypairs:
      self._keypair_combo.append_text(x.name)

    # if a keypair is specified in self._config, set the active keypair
    if selected_keypair:
      for i in range(0, len(self._keypairs)):
        if self._keypairs[i].name == selected_keypair:
          self._keypair_combo.set_active(i)
          break

  def validate(self):
    # make sure login info is valid
    conn = self.get_connection()

    if not conn:
      return [False, 'Cannot login to AWS. The ID and/or Password you specified are not correct.']

    # make sure there is a selected extra EBS volume
    if self._extra_volume.get_active() == -1:
      return [False, 'The extra EBS volume field cannot be left blank. ' + \
               'This is the volume from which the instance configuration script is loaded.']

    # make sure there is a selected keypair to use
    if self._keypair_combo.get_active() == -1:
      return [False, 'A keypair must be selected in order to launch instances.']

    return [True, None]

  def run(self):
    while True:
      response = gtk.Dialog.run(self)

      if response != gtk.RESPONSE_OK:
        return response

      valid, error = self.validate()

      if not valid:
        display_error_msg(self, error)
      else:
        # set _config data based on what was selected in the dialog
        self._config.ec2qs_id = self._login_id.get_text()
        self._config.ec2qs_pass = self._login_pass.get_text()

        if self._extra_volume.get_active() == -1:
          self._config.extra_volume_id = None
        else:
          self._config.extra_volume_id = self._volumes[self._extra_volume.get_active()].id

        if self._keypair_combo.get_active() == -1:
          self._config.keypair_name = None
        else:
          self._config.keypair_name = self._keypairs[self._keypair_combo.get_active()].name

        self._config.ssh_passwords = self._ssh_passwords
        self._config.ssh_usernames = self._ssh_usernames

        return response

class OperationExecutionError(Exception):

  def __init__(self, msg):
    self.msg = msg

  def __str__(self):
    return self.msg

class OperationStep(object):

  # TODO: Is there no way to avoid this? Can't get the type during construction or __call__, since
  # the class is still being created. Have to use a string then.
  operation_counts = {}

  # TODO: Is there a way to get the operation type from either self or f (in  __call__ below)? Wouldn't need the
  # optype argument if so
  def __init__(self, optype, text, threshold=1, waitsecs=0):
    if optype in OperationStep.operation_counts:
      OperationStep.operation_counts[optype] = OperationStep.operation_counts[optype] + 1
    else:
      OperationStep.operation_counts[optype] = 1

    self.optype = optype
    self.progress_text = text
    self.threshold = threshold
    self.waitsecs = waitsecs

  def __call__(self, f):
    def wrapped(opself, progress):
      # if this is the first time we're trying this step, set the progress
      if opself._OperationBase__attempts == 0:
        progress.progress_made(self.progress_text)

      result = None

      # if the threshold is 1, make sure exceptions are propagated so the user sees them immediately
      if self.threshold == 1:
        result = f(opself, progress)
        return result
      else:
        try:
          result = f(opself, progress)
          opself._OperationBase__attempts = 0
          return result
        except:
          progress.log('Failed: ' + str(sys.exc_value))

          opself._OperationBase__attempts = opself._OperationBase__attempts + 1

          if opself._OperationBase__attempts == self.threshold:
            raise OperationExecutionError('Failed too many times. Inspect the log for more info.')

          return self.waitsecs

    return wrapped

def operation_inherits(derived, base):
  OperationStep.operation_counts[derived] = \
    OperationStep.operation_counts[derived] + OperationStep.operation_counts[base]

class OperationBase:

  def __init__(self):
    self.__attempts = 0
    self.__task = None

  def modify_progress_window(self, progress):
    return

def perform_operation_rollback(parent, rollback_ops):
  for rollback in rollback_ops:
    try:
      rollback()
    except:
      display_error_msg(parent, 'Unexpected rollback error: ' + str(sys.exc_value))

def execute_operation_step(parent, composite_op):
  progress = ProgressDialog(parent, OperationStep.operation_counts[composite_op.__class__.__name__])
  rollback_ops = []
  waitmsg = None
  result = None
  waitsecs = None
  function = None
  rollback = None

  # customize the progress dialog
  composite_op.modify_progress_window(progress)

  # put a log entry so the window isn't so barren
  progress.log('Executing...')

  # initial call is just for getting a generator, so yield here
  yield True

  # get the initial operation info
  single_op = composite_op.initial_operation
  while single_op:
    # if the composite operation was cancelled, rollback anything that needs to be rolled back
    if progress.is_cancelled == True:
      perform_operation_rollback(parent, rollback_ops)
      progress.cancelled()
      break

    # if we're waiting, update the log and yield True
    if waitsecs != None:
      # decrement the wait counter
      waitsecs = waitsecs - 1

      # update the log file
      progress.replace_last_log(waitmsg % waitsecs)

      # if we're done waiting, put the generator back as an idle event and yield False
      if waitsecs == 0:
        waitsecs = None
        # TODO: Is there a better way of accessing a base class' attributes?
        gobject.idle_add(composite_op._OperationBase__task.next)
        yield False
      else:
        yield True
    else:
      # break the single op information down
      function = single_op[0]
      rollback = single_op[1]

      # if there is a rollback function for this op, prepend it to the list of rollback ops
      if rollback:
        rollback_ops.insert(0, rollback)

      # execute the step and get the next step to execute (if any)
      result = None
      try:
        result = function(progress)
      except OperationExecutionError:
        perform_operation_rollback(parent, rollback_ops)
        display_error_msg(parent, str(sys.exc_value))
        progress.failed()
        break
      except:
        perform_operation_rollback(parent, rollback_ops)
        display_error_msg(parent, 'Unexpected error: ' + str(sys.exc_value))
        progress.failed()
        break

      if not result:
        progress.done()
        break

      # OperationStep's wrapped function will return a time interval (an int), if it wants to wait
      # in this case, we must add the task as a timeout handler and yield false, while still in
      # the while loop
      if isinstance(result, int):
        waitsecs = result
        waitmsg = 'Waiting %i seconds before trying again...'
        progress.log(waitmsg % waitsecs)
        gobject.timeout_add(1000, composite_op._OperationBase__task.next)
        yield False
      elif len(result) == 3: # if we need to wait before running the next op step
        waitsecs = result[2]
        waitmsg = 'Waiting %i seconds...'
        progress.log(waitmsg % waitsecs)
        single_op = result
        gobject.timeout_add(1000, composite_op._OperationBase__task.next)
        yield False
      else:
        single_op = result
        yield True

  yield False

def execute_operation(parent, composite_op):
  composite_op._OperationBase__task = execute_operation_step(parent, composite_op)

  gobject.idle_add(composite_op._OperationBase__task.next)

# TODO: Really need my own nx client...
def create_nxs_file(ip):
  file_ = open('temp.nxs', 'w')
  file_.write("\
<!DOCTYPE NXClientSettings>\n\
<NXClientSettings application=\"nxclient\" version=\"1.3\" >\n\
<group name=\"Advanced\" >\n\
<option key=\"Cache size\" value=\"128\" />\n\
<option key=\"Cache size on disk\" value=\"128\" />\n\
<option key=\"Current keyboard\" value=\"true\" />\n\
<option key=\"Custom keyboard layout\" value=\"\" />\n\
<option key=\"Disable DirectDraw\" value=\"false\" />\n\
<option key=\"Disable ZLIB stream compression\" value=\"false\" />\n\
<option key=\"Disable deferred updates\" value=\"false\" />\n\
<option key=\"Enable HTTP proxy\" value=\"false\" />\n\
<option key=\"Enable SSL encryption\" value=\"true\" />\n\
<option key=\"Enable response time optimisations\" value=\"false\" />\n\
<option key=\"Grab keyboard\" value=\"false\" />\n\
<option key=\"HTTP proxy host\" value=\"\" />\n\
<option key=\"HTTP proxy port\" value=\"8080\" />\n\
<option key=\"HTTP proxy username\" value=\"\" />\n\
<option key=\"Remember HTTP proxy password\" value=\"false\" />\n\
<option key=\"Restore cache\" value=\"true\" />\n\
<option key=\"StreamCompression\" value=\"\" />\n\
</group>\n\
<group name=\"Environment\" >\n\
<option key=\"Font server host\" value=\"\" />\n\
<option key=\"Font server port\" value=\"7100\" />\n\
<option key=\"Use font server\" value=\"false\" />\n\
</group>\n\
<group name=\"General\" >\n\
<option key=\"Automatic reconnect\" value=\"true\" />\n\
<option key=\"Command line\" value=\"\" />\n\
<option key=\"Custom Unix Desktop\" value=\"console\" />\n\
<option key=\"Desktop\" value=\"gnome\" />\n\
<option key=\"Disable SHM\" value=\"false\" />\n\
<option key=\"Disable emulate shared pixmaps\" value=\"false\" />\n\
<option key=\"Link speed\" value=\"wan\" />\n\
<option key=\"Remember password\" value=\"false\" />\n\
<option key=\"Resolution\" value=\"fullscreen\" />\n\
<option key=\"Resolution height\" value=\"1024\" />\n\
<option key=\"Resolution width\" value=\"768\" />\n\
<option key=\"Server host\" value=\"" + ip + "\" />\n\
<option key=\"Server port\" value=\"22\" />\n\
<option key=\"Session\" value=\"unix\" />\n\
<option key=\"Spread over monitors\" value=\"false\" />\n\
<option key=\"Use default image encoding\" value=\"0\" />\n\
<option key=\"Use render\" value=\"true\" />\n\
<option key=\"Use taint\" value=\"true\" />\n\
<option key=\"Virtual desktop\" value=\"false\" />\n\
<option key=\"XAgent encoding\" value=\"true\" />\n\
<option key=\"displaySaveOnExit\" value=\"true\" />\n\
<option key=\"xdm broadcast port\" value=\"177\" />\n\
<option key=\"xdm list host\" value=\"localhost\" />\n\
<option key=\"xdm list port\" value=\"177\" />\n\
<option key=\"xdm mode\" value=\"server decide\" />\n\
<option key=\"xdm query host\" value=\"localhost\" />\n\
<option key=\"xdm query port\" value=\"177\" />\n\
</group>\n\
<group name=\"Images\" >\n\
<option key=\"Disable JPEG Compression\" value=\"0\" />\n\
<option key=\"Disable all image optimisations\" value=\"false\" />\n\
<option key=\"Disable backingstore\" value=\"false\" />\n\
<option key=\"Disable composite\" value=\"false\" />\n\
<option key=\"Image Compression Type\" value=\"3\" />\n\
<option key=\"Image Encoding Type\" value=\"0\" />\n\
<option key=\"Image JPEG Encoding\" value=\"false\" />\n\
<option key=\"JPEG Quality\" value=\"6\" />\n\
<option key=\"RDP Image Encoding\" value=\"3\" />\n\
<option key=\"RDP JPEG Quality\" value=\"6\" />\n\
<option key=\"RDP optimization for low-bandwidth link\" value=\"false\" />\n\
<option key=\"Reduce colors to\" value=\"\" />\n\
<option key=\"Use PNG Compression\" value=\"true\" />\n\
<option key=\"VNC JPEG Quality\" value=\"6\" />\n\
<option key=\"VNC images compression\" value=\"3\" />\n\
</group>\n\
<group name=\"Login\" >\n\
<option key=\"Auth\" value=\"EMPTY_PASSWORD\" />\n\
<option key=\"Guest Mode\" value=\"false\" />\n\
<option key=\"Guest password\" value=\"\" />\n\
<option key=\"Guest username\" value=\"\" />\n\
<option key=\"Login Method\" value=\"nx\" />\n\
<option key=\"Public Key\" value=\"-----BEGIN DSA PRIVATE KEY-----\n\
MIIBuwIBAAKBgQCXv9AzQXjxvXWC1qu3CdEqskX9YomTfyG865gb4D02ZwWuRU/9\n\
C3I9/bEWLdaWgJYXIcFJsMCIkmWjjeSZyTmeoypI1iLifTHUxn3b7WNWi8AzKcVF\n\
aBsBGiljsop9NiD1mEpA0G+nHHrhvTXz7pUvYrsrXcdMyM6rxqn77nbbnwIVALCi\n\
xFdHZADw5KAVZI7r6QatEkqLAoGBAI4L1TQGFkq5xQ/nIIciW8setAAIyrcWdK/z\n\
5/ZPeELdq70KDJxoLf81NL/8uIc4PoNyTRJjtT3R4f8Az1TsZWeh2+ReCEJxDWgG\n\
fbk2YhRqoQTtXPFsI4qvzBWct42WonWqyyb1bPBHk+JmXFscJu5yFQ+JUVNsENpY\n\
+Gkz3HqTAoGANlgcCuA4wrC+3Cic9CFkqiwO/Rn1vk8dvGuEQqFJ6f6LVfPfRTfa\n\
QU7TGVLk2CzY4dasrwxJ1f6FsT8DHTNGnxELPKRuLstGrFY/PR7KeafeFZDf+fJ3\n\
mbX5nxrld3wi5titTnX+8s4IKv29HJguPvOK/SI7cjzA+SqNfD7qEo8CFDIm1xRf\n\
8xAPsSKs6yZ6j1FNklfu\n\
-----END DSA PRIVATE KEY-----\n\
\" />\n\
<option key=\"User\" value=\"ubuntu\" />\n\
</group>\n\
<group name=\"Services\" >\n\
<option key=\"Audio\" value=\"false\" />\n\
<option key=\"IPPPort\" value=\"631\" />\n\
<option key=\"IPPPrinting\" value=\"false\" />\n\
<option key=\"Shares\" value=\"false\" />\n\
</group>\n\
<group name=\"VNC Session\" >\n\
<option key=\"Display\" value=\"0\" />\n\
<option key=\"Remember\" value=\"false\" />\n\
<option key=\"Server\" value=\"\" />\n\
</group>\n\
<group name=\"Windows Session\" >\n\
<option key=\"Application\" value=\"\" />\n\
<option key=\"Authentication\" value=\"2\" />\n\
<option key=\"Color Depth\" value=\"8\" />\n\
<option key=\"Domain\" value=\"\" />\n\
<option key=\"Image Cache\" value=\"true\" />\n\
<option key=\"Password\" value=\"EMPTY_PASSWORD\" />\n\
<option key=\"Remember\" value=\"true\" />\n\
<option key=\"Run application\" value=\"false\" />\n\
<option key=\"Server\" value=\"\" />\n\
<option key=\"User\" value=\"\" />\n\
</group>\n\
<group name=\"share chosen\" >\n\
<option key=\"Share number\" value=\"0\" />\n\
</group>\n\
</NXClientSettings>")

class StartAmiOp(OperationBase):

  CONNECT_RESPONSE = 0

  def __init__(self, app, image_id):
    OperationBase.__init__(self)
  
    # init members
    self.app = app
    self.image_id = image_id
    self.block_rd = False
    self.program_args = None
    self.creation_flags = None
    self.sgrp = None
    self.reconnect_btn = None

    # init all_operations list
    self.initial_operation = [self.get_connection, None]

  def modify_progress_window(self, progress):
    self.reconnect_btn = progress.add_button('Reconnect', StartAmiOp.CONNECT_RESPONSE)
    self.reconnect_btn.props.sensitive = False
    self.reconnect_btn.connect('clicked', lambda (w): self.connect_to_instance_impl(False))

  @OperationStep('StartAmiOp', 'Connecting to AWS...')
  def get_connection(self, progress):
    self.conn = self.app.get_connection()
    return [self.get_ami_details, None]

  @OperationStep('StartAmiOp', 'Getting AMI details...')
  def get_ami_details(self, progress):
    # get the image
    self.image = self.conn.get_image(self.image_id)

    # if no image, abort
    if self.image == None:
      raise OperationExecutionError('Could not find \'' + self.image_id + '\' image.')

    # set platform specific launching details
    # TODO: all instance vars used need to be initialized in the constructor
    self.user = self.app._config.ssh_usernames[self.image_id]
    self.pwd = self.app._config.ssh_passwords[self.image_id]
    if self.image.platform == 'windows':
      self.device = 'xvdf'
      self.commands = [
        '/cygdrive/d/setup.sh'
      ]
      self.setuploc = '/cygdrive/d/setup.sh'
    else:
      self.device = 'sdf'
      self.commands = [
        'echo "%s" | sudo mount /dev/sdf1 ~/extra_volume' % self.pwd,
        '~/extra_volume/setup.sh'
      ]

    return [self.get_ebs_volume, None]

  @OperationStep('StartAmiOp', 'Getting extra EBS volume details...')
  def get_ebs_volume(self, progress):
    # find the ebs volume to attach
    self.ebs = self.conn.get_all_volumes([self.app._config.extra_volume_id])[0]

    # if can't find the volume, abort
    if self.ebs == None:
      raise OperationExecutionError('Could not find the \'' + self.app._config.extra_volume_id + '\' volume.')

    return [self.get_ip_address, None]

  @OperationStep('StartAmiOp', 'Getting public IP address...', threshold=GET_IP_FAILURE_THRESHOLD, waitsecs=10)
  def get_ip_address(self, progress):
    # get public ip address of this computer
    # TODO: The website used should be configurable.
    handle = urllib2.urlopen('http://www.whatismyip.com/automation/n09230945.asp')
    self.ip = handle.read()
    handle.close()

    if self.ip == None or self.ip.strip() == '':
      raise OperationExecutionError('Could not obtain the public IP address of this computer.')

    progress.log('Found public IP address, ' + self.ip)

    return [self.create_security_group, self.remove_security_group]

  @OperationStep('StartAmiOp', 'Creating security group...')
  def create_security_group(self, progress):
    self.sgrp = self.conn.create_security_group( \
      TEMP_SECURITY_GROUP_NAME + '_' + self.image.name, 'ec2quickstart temporary security group')

    # add all rules
    for x in self.app._config.security_rules:
      progress.some_progress_made()

      protocol = 'tcp' if x.protocol == SecurityGroupRule.PROTOCOL_TCP else 'udp';
      cidr = (self.ip + '/32') if x.ip == SecurityGroupRule.IP_ME else '0.0.0.0/0';
    
      self.sgrp.authorize(ip_protocol = protocol, from_port = x.port_from, \
        to_port = x.port_to, cidr_ip = cidr)

    return [self.launch_instance, self.terminate_instance]

  def remove_security_group(self):
    sgroups = self.conn.get_all_security_groups()
    for x in sgroups:
      if x.name == TEMP_SECURITY_GROUP_NAME + '_' + self.image.name:
        x.delete()

  @OperationStep('StartAmiOp', 'Launching instance...')
  def launch_instance(self, progress):
    # launch an instance
    res = self.image.run( \
      security_groups = [self.sgrp.name], \
      placement = self.ebs.zone, \
      key_name = self.app._config.keypair_name)

    self.inst = res.instances[0]

    return [self.wait_for_instance, None]

  def terminate_instance(self):
    self.inst.terminate()

  @OperationStep('StartAmiOp', 'Waiting for instance to start...', threshold=-1, waitsecs=30)
  def wait_for_instance(self, progress):
    self.inst.update()

    if self.inst.state == 'pending':
      raise OperationExecutionError('Instance still pending.')

    progress.log('Instance started at ' + self.inst.public_dns_name)

    return [self.connect_via_ssh, None]

  @OperationStep('StartAmiOp', 'Connecting via SSH...', threshold=CONNECT_SSH_FAILURE_THRESHOLD, waitsecs=60)
  def connect_via_ssh(self, progress):
    self.ssh_connection = paramiko.Transport((self.inst.public_dns_name, 22))
    self.ssh_connection.connect(username = self.user, password = self.pwd)

    return [self.attach_ebs_volume, None]

  @OperationStep('StartAmiOp', 'Attaching extra volume...')
  def attach_ebs_volume(self, progress):
    # attach the desired ebs volume.
    self.ebs.attach(self.inst.id, self.device)

    # wait for instance to see volume.
    progress.some_progress_made('Waiting for instance to see volume...')

    return [self.execute_setup_script, None, 10]

  @OperationStep('StartAmiOp', 'Executing setup script...')
  def execute_setup_script(self, progress):
    # run setup.sh using the ssh connection
    try:
      lines = []

      for command in self.commands:
        channel = self.ssh_connection.open_session()
        channel.exec_command(command)
        
        output = channel.makefile('rb', -1).readlines()
        if not output:
          output = channel.makefile_stderr('rb', -1).readlines()

        lines.extend(output)

      progress.log('output: ')
      for line in lines:
        progress.log(line)
    except:
      display_error_msg(self.app.window, 'Unexpected error: ' + sys.exc_info()[0])

    return [self.close_ssh_connection, None]

  @OperationStep('StartAmiOp', 'Closing SSH connection...')
  def close_ssh_connection(self, progress):
    # exit ssh
    try:
      self.ssh_connection.close()
    except:
      display_error_msg('Unexpected error: ' + sys.exc_info()[0])

    # TODO: Should be able to specify next + rollback function in OperationStep decorator, instead of return.
    # If next is specified this way, though, overloading virtual functions won't work quite right.
    # Store next/rollback in 'f'?
    return [self.connect_to_instance, None, 60]

  def connect_to_instance_impl(self, block):
    # set the creation flags to block or not block
    creation_flags = 0
    if block == False:
      creation_flags = DETACHED_PROCESS

    # pick the remote desktop program to use
    if self.image.platform == 'windows':
      self.program_args = ['mstsc.exe', '/v:' + self.inst.public_dns_name, '/console', '/f']
    else:
      create_nxs_file(self.inst.public_dns_name)
      self.program_args = ['C:\Program Files\NX Client for Windows\\nxclient.exe', '--session', 'temp.nxs']

    # launch the remote desktop client
    sp = subprocess.Popen(self.program_args, creationflags=creation_flags)

    if block:
      sp.wait()

  @OperationStep('StartAmiOp', 'Connecting to instance...')
  def connect_to_instance(self, progress):
    self.connect_to_instance_impl(False)
    self.reconnect_btn.props.sensitive = True
    return None

class UpdateAmiOp(StartAmiOp):

  ABORT_RESPONSE = 0

  def __init__(self, app, image_id):
    StartAmiOp.__init__(self, app, image_id)
    operation_inherits('UpdateAmiOp', 'StartAmiOp') # TODO: use metaclasses to get rid of this. if possible.

  def modify_progress_window(self, progress):
    return

  def close_ssh_connection(self, progress):
    StartAmiOp.close_ssh_connection(self, progress)
    return [self.customize_instance, None, 60]

  def terminate_instance(self):
    display_info_msg(self.app.window, 'Not terminating customized instance. Terminate it through the AWS console.')
    return

  @OperationStep('UpdateAmiOp', 'Customizing instance...')
  def customize_instance(self, progress):
    # ask if any further customization is needed
    need_customization = ask_yes_no(self.app.window, 'Does the AMI need customization outside of running setup.sh?')

    # if yes, rdp/nx to machine (launch as child process)
    if need_customization:
      reconnect = True

      response = gtk.RESPONSE_YES
      while response == gtk.RESPONSE_YES:
        StartAmiOp.connect_to_instance_impl(self, True)

        # create and run the message window
        msg_win = gtk.MessageDialog(progress, gtk.DIALOG_MODAL, gtk.MESSAGE_QUESTION, \
          gtk.BUTTONS_YES_NO, 'Do you need to reconnect?')
        msg_win.add_button('Abort', self.ABORT_RESPONSE)
        response = msg_win.run()

        # destroy the message window now that its not needed
        msg_win.destroy()

        if response == self.ABORT_RESPONSE:
          raise OperationExecutionError('Aborted.')

    return [self.shutdown_instance, None]

  @OperationStep('UpdateAmiOp', 'Shutting down instance...')
  def shutdown_instance(self, progress):
    self.inst.stop()

    return [self.wait_for_instance_to_stop, None]

  @OperationStep('UpdateAmiOp', 'Waiting for instance to stop...', threshold=-1, waitsecs=60)
  def wait_for_instance_to_stop(self, progress):
    self.inst.update()
    print inst.state
    if inst.state != 'stopped':
      raise OperationExecutionError('Instance still running.')

    return [self.detach_volume, None]

  @OperationStep('UpdateAmiOp', 'Detaching extra volume...')
  def detach_volume(self, progress):
    # detach volume
    self.ebs.detach()

    return [self.create_ami, self.deregister_ami_rollback]

  @OperationStep('UpdateAmiOp', 'Creating new image...')
  def create_ami(self, progress):
    # when done customizing, begin ami creation
    self.new_ami_id = self.conn.create_image( \
      self.inst.id, alternate_image_name(self.image.name), self.image.description)

    return [self.wait_for_ami, None]

  def deregister_ami_rollback(self):
    self.conn.get_image(self.new_ami_id).deregister()
    self.delete_old_snapshots(self.new_ami_id)

  @OperationStep('UpdateAmiOp', 'Waiting for image to be created...', threshold = -1, waitsecs = 120)
  def wait_for_ami(self, progress):
    img = self.conn.get_image(self.new_ami_id)
    if img.state != 'available':
      raise OperationExecutionError('AMI state is \'%s\', waiting for \'available\'...' % img.state)

    return [self.terminate_launched_instance, None]

  @OperationStep('UpdateAmiOp', 'Terminating instance...')
  def terminate_launched_instance(self, progress):
    # terminate instance
    self.inst.terminate()

    return [self.update_config, self.revert_config]

  @OperationStep('UpdateAmiOp', 'Updating ec2quickstart configuration...')
  def update_config(self, progress):
    self.old_ami_id = self.image.id

    self.app._config.ssh_usernames[self.new_ami_id] = self.app._config.ssh_usernames[self.old_ami_id]
    self.app._config.ssh_passwords[self.new_ami_id] = self.app._config.ssh_passwords[self.old_ami_id]
    del self.app._config.ssh_usernames[self.old_ami_id]
    del self.app._config.ssh_passwords[self.old_ami_id]

    self.app.save_config()

    return [self.deregister_ami, None]

  def revert_config(self):
    self.app._config.ssh_usernames[self.old_ami_id] = self.app._config.ssh_usernames[self.new_ami_id]
    self.app._config.ssh_passwords[self.old_ami_id] = self.app._config.ssh_passwords[self.new_ami_id]
    del self.app._config.ssh_usernames[self.new_ami_id]
    del self.app._config.ssh_passwords[self.new_ami_id]

    self.app.save_config()

  def delete_old_snapshots(self, image_id):
    snapshots = self.conn.get_all_snapshots(owners = ['self'])

    for snap in snapshots:
      if snap.description.find('Created by CreateImage') != -1 and snap.description.find(image_id) != -1:
        snap.delete()

  @OperationStep('UpdateAmiOp', 'Deleting old AMI...')
  def deregister_ami(self, progress):  
    # delete old AMI
    self.image.deregister()

    # delete old snapshots
    self.delete_old_snapshots(self.image.id)

    display_info_msg(self.app.window, \
      'The AMI has been updated. Please modify the setup script the next time an instance is launched.')

    return [self.delete_temp_sg, None]

  @OperationStep('UpdateAmiOp', 'Deleting temporary security group...')
  def delete_temp_sg(self, progress):
    # delete temporary security group
    sgroups = self.conn.get_all_security_groups()
    for x in sgroups:
      if x.name == TEMP_SECURITY_GROUP_NAME + '_' + self.image.name:
        x.delete()

    return None

class ResnapshotOp(OperationBase):

  def __init__(self, app):
    OperationBase.__init__(self)

    self.app = app

    self.initial_operation = [self.get_connecton, None]

  @OperationStep('ResnapshotOp', 'Connecting to AWS...')
  def get_connection(self, progress):
    self.conn = self.app.get_connection()
    return [self.get_ebs_volume, None]

  @OperationStep('ResnapshotOp', 'Getting extra EBS volume details...')
  def get_ebs_volume(self, progress):
    # find the ebs volume to attach
    self.ebs = self.conn.get_all_volumes([self.app._config.extra_volume_id])[0]

    # if can't find the volume, abort
    if self.ebs == None:
      raise OperationExecutionError('Could not find the \'' + self.app._config.extra_volume_id + '\' volume.')

    return [self.snapshot_vol, self.delete_snapshot]

  @OperationStep('ResnapshotOp', 'Creating snapshot...')
  def snapshot_vol(self, progress):
    self.snapshot = self.ebs.create_snapshot(str(datetime.utcnow()))

    return [self.wait_for_snapshot, None]

  def delete_snapshot(self):
    self.snapshot.delete()

  @OperationStep('ResnapshotOp', 'Waiting for snapshot to be created...', threshold=-1, waitsecs=30)
  def wait_for_snapshot(self, progress):
    if self.conn.get_snapshot(self.snapshot.id).status == 'pending':
      raise OperationExecutionError('dummy')

    return [self.delete_old_snapshot, None]

  @OperationStep('ResnapshotOp', 'Deleting the old snapshot...')
  def delete_old_snapshot(self, progress):
    snapshots = self.conn.get_all_snapshots()
    for snap in snapshots:
      if snap.id != self.snapshot.id and snap.volume_id == self.ebs.id:
        snap.delete()

    return None

class TerminateOp(OperationBase):

  def __init__(self, app):
    OperationBase.__init__(self)

    self.app = app
    self.sgroup = None

    self.initial_operation = [self.get_connection, None]

  @OperationStep('TerminateOp', 'Connecting to AWS...')
  def get_connection(self, progress):
    self.conn = self.app.get_connection()
    return [self.terminate_instances, None]

  @OperationStep('TerminateOp', 'Terminating instances...')
  def terminate_instances(self, progress):
    sgroups = self.conn.get_all_security_groups()
    for x in sgroups:
      if x.name.startswith(TEMP_SECURITY_GROUP_NAME):
        self.sgroup = x
        break;

    for x in self.sgroup.instances():
      progress.some_progress_made('Terminating \'' + x.id + '\'...')
      x.terminate()

    return [self.delete_temp_security_grp, None]

  @OperationStep('TerminateOp', 'Deleting temporary security group...')
  def delete_temp_security_grp(self, progress):
    if self.sgroup:
      self.sgroup.delete()

    return None

# TODO: This should derive from gtk.Window
class MainWindow:

  def __init__(self):
    # init private members
    self._connection = None
    self._config = None

    # create a new window
    self.window = gtk.Window(gtk.WINDOW_TOPLEVEL)

    # connect callbacks
    self.window.connect('destroy', self.destroy)
  
    # set window properties
    self.window.set_border_width(10)
    
    # create the vbox to hold widgets in
    self.box = gtk.VBox(False, 15)
    self.window.add(self.box)

    # create ec2 function buttons
    self.edit_config_btn = gtk.Button('Edit Configuration')
    self.start_ami_btn = gtk.Button('Start AMI')
    self.update_amis_btn = gtk.Button('Update AMI')
    self.resnapshot_btn = gtk.Button('Resnapshot Volumes')
    self.terminate_btn = gtk.Button('Terminate All')

    # connect buttons
    self.edit_config_btn.connect('clicked', self.edit_config)
    self.start_ami_btn.connect('clicked', self.start_ami)
    self.update_amis_btn.connect('clicked', self.update_ami)
    self.resnapshot_btn.connect('clicked', self.resnapshot)
    self.terminate_btn.connect('clicked', self.terminate_all)
    
    # add buttons to the vbox
    self.box.pack_start(self.edit_config_btn, False, False, 0)
    self.box.pack_start(self.start_ami_btn, False, False, 0)
    self.box.pack_start(self.update_amis_btn, False, False, 0)
    self.box.pack_start(self.resnapshot_btn, False, False, 0)
    self.box.pack_start(self.terminate_btn, False, False, 0)

    # show all widgets
    self.window.show_all()

  def set_button_sensitivity(self, sensitive):
    self.edit_config_btn.props.sensitive = sensitive
    self.start_ami_btn.props.sensitive = sensitive
    self.update_amis_btn.props.sensitive = sensitive
    self.resnapshot_btn.props.sensitive = sensitive
    self.terminate_btn.props.sensitive = sensitive

  def destroy(self, widget):
    # closing the connection results in an exception...
    gtk.main_quit()

  def create_config(self):
    self._config = Config()

    # TODO: Need to specify here that config editing cannot be cancelled.
    # create GUI and get user input
    config_window = ConfigDialog(self, self._config)

    response = config_window.run()
    config_window.destroy()

    if response != gtk.RESPONSE_OK:
      return False

    return self.save_config()

  def save_config(self):
    # remove any existing config file
    if os.path.exists(CONFIG_FILE_NAME):
      os.remove(CONFIG_FILE_NAME)

    # open the config file for writing
    config_file = open(CONFIG_FILE_NAME, 'wb')

    # TODO: Would really like this to be an XML file.
    # save the config
    pickle.dump(self._config, config_file)

    return True

  def load_config(self):
    # if the file exists, load the config file
    if os.path.exists(CONFIG_FILE_NAME):
      config_file = open(CONFIG_FILE_NAME, 'rb')
      self._config = pickle.load(config_file)
      return True
    else: # if the file doesn't exist, create & save the config file
      return self.create_config()

  def get_connection(self):
    if self._connection == None:
      self._connection = connection.EC2Connection(self._config.ec2qs_id, self._config.ec2qs_pass)
    return self._connection

  def start_ami(self, widget):
    # ask which AMI to launch
    ami = PickAMIDialog(self.window, self.get_connection(), self._config.ssh_usernames.keys()).run_and_return()

    if not ami:
      return

    execute_operation(self.window, StartAmiOp(self, ami.id))
    
  def update_ami(self, widget):
    # ask which AMI to update
    ami = PickAMIDialog(self.window, self.get_connection(), self._config.ssh_usernames.keys()).run_and_return()

    if not ami:
      return

    execute_operation(self.window, UpdateAmiOp(self, ami.id))

  def resnapshot(self, widget):
    execute_operation(self.window, ResnapshotOp(self))

  def terminate_all(self, widget):
    execute_operation(self.window, TerminateOp(self))

  def edit_config(self, widget):
    config_window = ConfigDialog(self, self._config)
    config_window.run()
    config_window.destroy()
    self.save_config()

  def main(self):
    # load configuration
    success = self.load_config()

    if success:
      gtk.main()

# if the program is run directly or passed as an argument to the python
# interpreter, run the app
if __name__ == '__main__':
  MainWindow().main()