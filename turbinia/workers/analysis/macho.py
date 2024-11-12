"""Task for analysing Mach-O Information."""

import json
import os
import time

from time import strftime
from turbinia import TurbiniaException
from typing import List

from turbinia.evidence import EvidenceState as state
from turbinia.evidence import ReportText
from turbinia.lib import text_formatter as fmt
from turbinia.workers import Priority
from turbinia.workers import TurbiniaTask


class Architecture(object):

  def __init__(self):
    self.x86_64 = False
    self.arm64 = False


class Hashes(object):

  def __init__(self):
    self.sha256 = ""
    self.md5 = ""
    self.ssdeep = ""
    self.tlsh = ""
    self.symhash = ""


class Section(object):

  def __init__(self, flags: List[str]):
    self.name = ""
    self.entropy = 0
    self.address = ""
    self.size = ""
    self.offset = ""
    self.section_type = ""
    self.flags = flags


class Segment(object):

  def __init__(self, sections: List[Section]):
    self.name = ""
    self.offset = ""
    self.size = ""
    self.vaddr = ""
    self.vsize = ""
    self.sections = sections


class Import(object):

  def __init__(self):
    self.name = ""
    self.size = ""
    self.offset = ""


class ParsedBinary(object):

  def __init__(
      self, hashes: Hashes, segments: List[Segment], symbols: List[str],
      imports: List[Import], flags: List[str]):
    self.entropy = 0
    self.size = 0
    self.fat_offset = 0
    self.magic = ""
    self.flags = flags
    self.hashes = hashes
    self.segments = segments
    self.symbols = symbols
    self.imports = imports


class Export(object):

  def __init__(self):
    self.name = ""
    self.offset = ""


class ParsedFatBinary(object):

  def __init__(self, hashes: Hashes):
    self.size = 0
    self.entropy = 0
    self.hashes = hashes


class SignerInfo(object):

  def __init__(self):
    self.organization_name = ""
    self.organizational_unit_name = ""
    self.common_name = ""
    self.signing_time = ""
    self.cd_hash = ""
    self.message_digest = ""


class Signature(object):

  def __init__(self, signer_infos: List[SignerInfo]):
    self.signer_infos = signer_infos
    self.identifier = ""
    self.team_identifier = "not set"
    self.size = 0
    self.hash_type = ""
    self.hash_size = 0
    self.platform_identifier = 0
    self.pagesize = 0
    self.cd_hash_calculated = ""


class ParsedMacho(object):

  def __init__(
      self, signature: Signature, architecture: Architecture,
      exports: List[Export], fat_binary: ParsedFatBinary, arm64: ParsedBinary,
      x86_64: ParsedBinary):
    self.request = ""
    self.evidence = ""
    self.source_path = ""
    self.source_type = ""
    self.processing_time = 0
    self.signature = signature
    self.architecture = architecture
    self.exports = exports
    self.fat_binary = fat_binary
    self.arm64 = arm64
    self.x86_64 = x86_64


class MachoAnalysisTask(TurbiniaTask):
  """Task to analyse Mach-O Information"""

  REQUIRED_STATES = [state.ATTACHED, state.DECOMPRESSED]

  _MAGIC_MULTI_SIGNATURE = b'\xca\xfe\xba\xbe'
  _MAGIC_32_SIGNATURE = b'\xce\xfa\xed\xfe'
  _MAGIC_64_SIGNATURE = b'\xcf\xfa\xed\xfe'

  # Code signature constants
  # https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h
  _CSMAGIC_EMBEDDED_SIGNATURE = b'\xfa\xde\x0c\xc0'  # embedded form of signature data
  _CSMAGIC_CODEDIRECTORY = b'\xfa\xde\x0c\x02'  # CodeDirectory blob
  _CSMAGIC_BLOBWRAPPER = b'\xfa\xde\x0b\x01'  # Wrapper blob used for CMS Signature, among other things

  # Slot numbers
  # https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h
  _CSSLOT_CODEDIRECTORY = b'\x00\x00\x00\x00'  # Code Directory slot
  _CSSLOT_SIGNATURESLOT = b'\x00\x01\x00\x00'  # CMS Signature slot

  # n_type masks from /usr/include/mach-o/nlist.h
  _N_STAB = 0xe0  # 0b11100000 : Mask to get the stab information
  _N_PEXT = 0x10  # 0b00010000 : private external symbol bit
  _N_TYPE = 0x0e  # 0b00001110 : Mask to get the type bits
  _N_EXT = 0x01  # 0b00000001 : external symbol bit, set for external symbols

  def __init__(self, *args, **kwargs):
    super(MachoAnalysisTask, self).__init__(*args, **kwargs)
    if TurbiniaTask.check_worker_role():
      try:
        import lief
        import tlsh
        import pyssdeep
        from asn1crypto import cms
        from plaso.analyzers.hashers import entropy
        from plaso.analyzers.hashers import md5
        from plaso.analyzers.hashers import sha256

        self._cms = cms
        self._entropy = entropy
        self._lief = lief
        self._md5 = md5
        self._pyssdeep = pyssdeep
        self._sha256 = sha256
        self._tlsh = tlsh
      except ImportError as exception:
        message = f'Could not import libraries: {exception!s}'
        raise TurbiniaException(message)

  def _GetDigest(self, hasher, data):
    """Executes a hasher and returns the digest.
    Args:
      hasher (BaseHasher): hasher to execute.
      data (bytestring) : data to be hashed.
     Returns:
      digest (str): digest returned by hasher.
    """
    hasher.Update(data)
    return hasher.GetStringDigest()

  def _GetSymhash(self, binary):
    """Calculates Mach-O SymHash.
       https://www.anomali.com/fr/blog/symhash
    Args:
      binary (lief.MachO.Binary): binary to be parsed.
    Returns:
      symhash (str): symhash of the binary.
    """
    symbol_list = []
    for symbol in binary.imported_symbols:
      n_type = symbol.raw_type
      is_stab = n_type & self._N_STAB != 0
      is_external = n_type & self._N_EXT == self._N_EXT
      is_ntype = n_type & self._N_TYPE != 0
      if symbol.origin == self._lief._lief.MachO.Symbol.ORIGIN.LC_SYMTAB and not is_stab and is_external and not is_ntype:
        symbol_list.append(symbol.demangled_name)
    hasher = self._md5.MD5Hasher()
    hasher.Update(','.join(sorted(symbol_list)).encode())
    symhash = hasher.GetStringDigest()
    return symhash

  def _GetSections(self, segment):
    """Retrieves Mach-O segment section names.
    Args:
      segment (lief.MachO.SegmentCommand): segment to be parsed for sections.
    Returns:
      List[Section]: Sections of the segments.
    """
    sections = []
    for sec in segment.sections:
      flags = []
      section = Section(flags)
      section.name = sec.name
      section.entropy = sec.entropy
      section.address = hex(sec.virtual_address)
      section.size = hex(sec.size)
      section.offset = hex(sec.offset)
      section.section_type = str(sec.type).split(".")[-1]
      for flag in sec.flags_list:
        flags.append(str(flag).split(".")[-1])
      section.flags = flags
      sections.append(section)
    return sections

  def _GetSegments(self, binary):
    """Retrieves Mach-O segments.
    Args:
      binary (lief.MachO.Binary): binary to be parsed.
    Returns:
      List[Segment]: List of the segments.
    """
    segments = []
    for seg in binary.segments:
      sections = self._GetSections(seg)
      segment = Segment(sections)
      segment.name = seg.name
      segment.offset = hex(seg.file_offset)
      segment.size = hex(seg.file_size)
      segment.vaddr = hex(seg.virtual_address)
      segment.vsize = hex(seg.virtual_size)
      segments.append(segment)
    return segments

  def _GetSymbols(self, binary):
    """Retrieves Mach-O symbols.
    Args:
      binary (lief.MachO.Binary): binary to be parsed.
    Returns:
      List[str]: List of the symbols.
    """
    symbols = []
    for sym in binary.symbols:
      symbols.append(sym.demangled_name)
    return symbols

  def _CSHashType(self, cs_hash_type):
    """Translates CS hash type to a string.
    Args:
      cs_hash_type (int): CS hash type.
    Returns:
      (str): CS hash type string.
    """
    if cs_hash_type == 1:
      return "SHA1"
    elif cs_hash_type == 2:
      return "SHA256"
    elif cs_hash_type == 3:
      return "SHA256_TRUNCATED"
    elif cs_hash_type == 4:
      return "SHA384"
    else:
      return ""

  def _ParseCodeSignature(self, code_signature, result):
    """Parses Mach-O code signature.
       Details about the code signature structure on GitHub
       https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L267
    Args:
      code_signature (lief.MachO.CodeSignature): code signature to be parsed.
      result (TurbiniaTaskResult): The object to place task results into.
    Returns: Signature or None if not found
    """
    signature = None
    signature_bytes = code_signature.content.tobytes()
    super_blob_magic = signature_bytes[0:4]  # uint32_t magic
    if super_blob_magic == self._CSMAGIC_EMBEDDED_SIGNATURE:
      # SuperBlob called EmbeddedSignatureBlob found which contains the code signature data
      # struct EmbeddedSignatureBlob {
      #   uint32_t magic = 0xfade0cc0;
      #   uint32_t length;
      #   uint32_t count; // Count of contained blob entries
      #   IndexEntry entries[]; // Has `count` entries
      #   Blob blobs[]; // Has `count` blobs
      # }
      signature = Signature(signer_infos=[])
      super_blob_length = int.from_bytes(
          signature_bytes[4:8], "big")  # uint32_t length
      generic_blob_count = int.from_bytes(
          signature_bytes[8:12],
          "big")  # uint32_t count: Count of contained blob entries
      for i in range(generic_blob_count):
        # lets walk through the CS_BlobIndex index[] entries
        # https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L280C15-L280C22
        start_index_entry_type = 12 + i * 8  # uint32_t type
        start_index_entry_offset = start_index_entry_type + 4  # uint32_t offset
        blob_index_type = signature_bytes[
            start_index_entry_type:start_index_entry_type + 4]
        blob_index_offset = int.from_bytes(
            signature_bytes[start_index_entry_offset:start_index_entry_offset +
                            4], "big")
        generic_blob_magic = signature_bytes[
            blob_index_offset:blob_index_offset + 4]
        generic_blob_length = int.from_bytes(
            signature_bytes[blob_index_offset + 4:blob_index_offset + 8], "big")
        if generic_blob_magic == self._CSMAGIC_CODEDIRECTORY and blob_index_type == self._CSSLOT_CODEDIRECTORY:
          # CodeDirectory is a Blob the describes the binary being signed
          code_directory = signature_bytes[blob_index_offset:blob_index_offset +
                                           generic_blob_length]
          cd_hash_calculated = self._GetDigest(
              self._sha256.SHA256Hasher(), code_directory)
          if len(cd_hash_calculated) > 40:
            signature.cd_hash_calculated = cd_hash_calculated[0:40]
          cd_length = int.from_bytes(code_directory[4:8], "big")
          cd_hash_offset = int.from_bytes(code_directory[16:20], "big")
          cd_ident_offset = int.from_bytes(code_directory[20:24], "big")
          cd_hash_size = int.from_bytes(code_directory[36:37], "big")
          cd_hash_type = self._CSHashType(
              int.from_bytes(code_directory[37:38], "big"))
          cd_platform = int.from_bytes(code_directory[38:39], "big")
          cd_pagesize = 2**int.from_bytes(code_directory[39:40], "big")
          cd_team_id_offset = int.from_bytes(code_directory[48:52], "big")
          signature.hash_type = cd_hash_type
          signature.hash_size = cd_hash_size
          signature.platform_identifier = cd_platform
          signature.pagesize = cd_pagesize
          if cd_ident_offset > 0:
            cd_ident = code_directory[cd_ident_offset:-1].split(
                b'\0')[0].decode()
            signature.identifier = cd_ident
          if cd_team_id_offset > 0:
            cd_team_id = code_directory[cd_team_id_offset:-1].split(
                b'\0')[0].decode()
            signature.team_identifier = cd_team_id
        elif generic_blob_magic == self._CSMAGIC_BLOBWRAPPER and blob_index_type == self._CSSLOT_SIGNATURESLOT:
          signature.size = generic_blob_length
          blobwrapper_base = blob_index_offset + 8
          cert = signature_bytes[blobwrapper_base:blobwrapper_base +
                                 generic_blob_length]
          content_info = self._cms.ContentInfo.load(cert)
          if content_info['content_type'].native == 'signed_data':
            signed_data = content_info['content']
            signer_infos = signed_data['signer_infos']
            for signer_info in signer_infos:
              signer = SignerInfo()
              signed_attrs = signer_info['signed_attrs']
              for signed_attr in signed_attrs:
                signed_attr_type = signed_attr['type']
                signed_attr_values = signed_attr['values']
                if signed_attr_type.native == 'signing_time':
                  signer.signing_time = str(signed_attr_values.native[0])
                elif signed_attr_type.native == 'message_digest':
                  # https://forums.developer.apple.com/forums/thread/702351
                  signer.message_digest = signed_attr_values.native[0].hex()
                  if len(signed_attr_values.native[0]) > 20:
                    signer.cd_hash = signed_attr_values.native[0][0:20].hex()
                  else:
                    signer.cd_hash = signed_attr_values.native[0].hex()
              sid = signer_info['sid']
              issuer = sid.chosen['issuer'].chosen
              for entry in issuer:
                # https://datatracker.ietf.org/doc/html/rfc5652#section-10.2.4
                for sub_entry in entry:
                  # https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
                  name_type = sub_entry['type']
                  val = sub_entry['value']
                  if name_type.native == 'country_name':
                    signer.country_name = val.native
                  elif name_type.native == 'common_name':
                    signer.common_name = val.native
                  elif name_type.native == 'organization_name':
                    signer.organization_name = val.native
                  elif name_type.native == 'organizational_unit_name':
                    signer.organizational_unit_name = val.native
              signature.signer_infos.append(signer)
    else:
      result.log(f'no embedded code signature detected')
    return signature

  def _ParseMachoFatBinary(self, macho_fd, evidence, macho_path, file_name):
    """Parses a Mach-O fat binary.
    Args:
      macho_fd (int): file descriptor to the fat binary.
      evidence (Evidence object):  The evidence to process
      macho_path (str): path to the fat binary.
      file_name (str): file name of the fat binary.
    Returns:
      FatBinary: the parsed Mach-O Fat Binary details.
    """
    macho_fd.seek(0)
    data = macho_fd.read()
    hashes = Hashes()
    hashes.md5 = self._GetDigest(self._md5.MD5Hasher(), data)
    hashes.sha256 = self._GetDigest(self._sha256.SHA256Hasher(), data)
    hashes.tlsh = self._tlsh.hash(data)
    hashes.ssdeep = self._pyssdeep.get_hash_buffer(data)
    parsed_fat_binary = ParsedFatBinary(hashes)
    parsed_fat_binary.entropy = self._GetDigest(
        self._entropy.EntropyHasher(), data)
    fat_binary_stats = os.stat(macho_path)
    parsed_fat_binary.size = fat_binary_stats.st_size
    return parsed_fat_binary

  def _ParseMachoBinary(self, macho_fd, evidence, binary, result, file_name):
    """Parses a Mach-O binary.
    Args:
      macho_fd (int): file descriptor to the fat binary.
      evidence (Evidence object):  The evidence to process
      binary (lief.MachO.Binary): binary to be parsed.
      result (TurbiniaTaskResult): The object to place task results into.
      filename (str): file name of the binary.
    Returns:
      ParsedBinary: the parsed binary details.
    """
    fat_offset = binary.fat_offset
    binary_size = binary.original_size
    macho_fd.seek(fat_offset)
    data = macho_fd.read(binary_size)
    hashes = Hashes()
    hashes.md5 = self._GetDigest(self._md5.MD5Hasher(), data)
    hashes.sha256 = self._GetDigest(self._sha256.SHA256Hasher(), data)
    hashes.symhash = self._GetSymhash(binary)
    hashes.tlsh = self._tlsh.hash(data)
    hashes.ssdeep = self._pyssdeep.get_hash_buffer(data)
    parsed_binary = ParsedBinary(
        hashes=hashes, segments=None, symbols=None, imports=None, flags=None)
    parsed_binary.entropy = self._GetDigest(self._entropy.EntropyHasher(), data)
    parsed_binary.size = binary_size
    parsed_binary.fat_offset = fat_offset
    parsed_binary.magic = hex(binary.header.magic.value)
    parsed_binary.segments = self._GetSegments(binary)
    parsed_binary.symbols = self._GetSymbols(binary)
    flags = []
    for flag in binary.header.flags_list:
      flags.append(str(flag).split(".")[-1])
    parsed_binary.flags = flags
    imports = []
    for lib in binary.libraries:
      imp = Import()
      imp.name = lib.name
      imp.size = hex(lib.size)
      imp.offset = hex(lib.command_offset)
      imports.append(imp)
    parsed_binary.imports = imports

    if binary.has_code_signature:
      parsed_binary.signature = self._ParseCodeSignature(
          binary.code_signature, result)
    return parsed_binary

  def _WriteParsedMachoResults(self, file_name, parsed_macho, base_dir):
    """Outputs the parsed Mach-O results.
    Args:
        file_name(str): the name of the parsed Mach-O file
        parsed_macho(ParsedMacho): the parsed Mach-O details
        base_dir(str): the base directory for the parsed Mach-O file
    Returns:
        TurbiniaTaskResult object.
    """
    # Write the Mach-O Info to the output file.
    output_file_name = f'{file_name}.json'
    output_dir_path = os.path.join(self.output_dir, 'reports', base_dir)
    if not os.path.exists(output_dir_path):
      os.makedirs(output_dir_path)
    output_file_path = os.path.join(output_dir_path, output_file_name)
    with open(output_file_path, 'w') as fh:
      # Plain vanilla json.dumps() doesn't support custom classes.
      # https://stackoverflow.com/questions/3768895/how-to-make-a-class-json-serializable
      fh.write(
          f'{json.dumps(parsed_macho.__dict__, default=lambda o: o.__dict__, indent=2)}\n'
      )
      fh.close()

  def _CurrentTimeMillis(self):
    return round(time.time() * 1000)

  def run(self, evidence, result):
    """Run the Mach-O worker.
    Args:
        evidence (Evidence object):  The evidence to process
        result (TurbiniaTaskResult): The object to place task results into.
    Returns:
        TurbiniaTaskResult object.
    """
    # Where to store the resulting output file.
    start_time = self._CurrentTimeMillis()
    output_file_name = 'macho_analysis.txt'
    output_file_path = os.path.join(self.output_dir, output_file_name)

    # We output a report.
    output_evidence = ReportText(source_path=output_file_path)
    parsed_binaries = 0
    parsed_fat_binaries = 0

    # traverse root directory, and list directories as dirs and files as files
    for root, dirs, files in os.walk(evidence.local_path):
      for file in files:
        base_dir = os.path.relpath(root, evidence.local_path)
        macho_path = os.path.join(root, file)
        try:
          macho_binary = self._lief.MachO.parse(
              macho_path, config=self._lief.MachO.ParserConfig.quick)
          macho_fd = open(macho_path, 'rb')
        except IOError as e:
          # 'Error opening Mach-O file: {0:s}'.format(str(e)))
          break

        if isinstance(macho_binary, self._lief.MachO.FatBinary):
          architecture = Architecture()
          parsed_macho = ParsedMacho(
              signature=None, architecture=None, exports=None, fat_binary=None,
              arm64=None, x86_64=None)
          parsed_macho.evidence = evidence.id
          parsed_macho.request = evidence.request_id
          parsed_macho.source_path = file
          parsed_macho.source_type = "file"
          parsed_macho.fat_binary = self._ParseMachoFatBinary(
              macho_fd, evidence, macho_path, file)
          parsed_fat_binaries += 1
          for binary in macho_binary:
            parsed_binary = self._ParseMachoBinary(
                macho_fd, evidence, binary, result, file)
            parsed_binaries += 1
            if binary.header.cpu_type == self._lief.MachO.Header.CPU_TYPE.ARM64:
              parsed_macho.arm64 = parsed_binary
              architecture.arm64 = True
            elif binary.header.cpu_type == self._lief.MachO.Header.CPU_TYPE.X86_64:
              parsed_macho.x86_64 = parsed_binary
              architecture.x86_64 = True
          parsed_macho.architecture = architecture
          parsed_macho.processing_time = self._CurrentTimeMillis() - start_time
          self._WriteParsedMachoResults(file, parsed_macho, base_dir)
        elif isinstance(macho_binary, self._lief.MachO.Binary):
          result.log(
              f'Skipping unsupported top level lief.MachO.Binary: {file}')
        macho_fd.close()

    summary = f'Parsed {parsed_fat_binaries} lief.MachO.FatBinary and {parsed_binaries} lief.MachO.Binary'
    output_evidence.text_data = summary
    result.report_data = summary
    result.report_priority = Priority.LOW

    # Write the Mach-O Info to the output file.
    with open(output_file_path, 'wb') as fh:
      fh.write(output_evidence.text_data.encode('utf8'))
      fh.write('\n'.encode('utf8'))
      fh.close()

    # Add the output evidence to the result object.
    result.add_evidence(output_evidence, evidence.config)
    result.close(self, success=True, status=summary)

    return result