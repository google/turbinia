"""Task for analysing Mach-O Information."""

import json
import lief
import os

from typing import List

from turbinia import TurbiniaException

from asn1crypto import cms

from plaso.analyzers.hashers import entropy
from plaso.analyzers.hashers import md5
from plaso.analyzers.hashers import sha256

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

class Section():
    def __init__(self, flags: List[str]):
        self.name = ""
        self.entropy = 0
        self.address = ""
        self.size = ""
        self.offset = ""
        self.section_type = ""
        self.flags = flags

class Segment():
    def __init__(self, sections: List[Section]):
        self.command = ""
        self.name = ""
        self.offset = ""
        self.size = 0
        self.vaddr = ""
        self.vsize = 0
        self.sections = sections

class ParsedBinary(object):
    def __init__(self, hashes: Hashes, segments: List[Segment], symbols: List[str]):
        self.entropy = 0
        self.size = 0
        self.fat_offset = 0
        self.magic = ""
        self.flags = 0
        self.hashes = hashes
        self.segments = segments
        self.symbols = symbols

class Export(object):
    def __init__(self):
        self.name = ""
        self.offset = ""

class ParsedFatBinary(object):
    def __init__(self, hashes: Hashes):
        self.size = 0
        self.entropy = 0
        self.hashes = hashes

class Import(object):
    def __init__(self):
        self.dylib = ""
        self.name = "" 

class Iocs(object):
    def __init__(self, domains: List[str], urls: List[str], ips: List[str]):
        self.domains = domains
        self.urls = urls
        self.ips = ips

class Signature(object):
    def __init__(self):
        self.organization_name = ""
        self.organization_unit_name = ""
        self.common_name = ""
        self.identifier = ""
        self.team_identifier = ""
        self.signed_time = ""
        self.size = 0
        self.cd_hash = 0

class ParsedMacho(object):
  def __init__(self, signature: Signature, architecture: Architecture, iocs: Iocs, imports: List[Import], exports: List[Export], fat_binary: ParsedFatBinary, arm64: ParsedBinary, x86_64: ParsedBinary):
        self.request = ""
        self.evidence = ""
        self.source_path = ""
        self.source_type = ""
        self.processing_time = 0
        self.signature = signature
        self.architecture = architecture
        self.iocs = iocs
        self.imports = imports
        self.exports = exports
        self.fat_binary = fat_binary
        self.arm64 = arm64
        self.x86_64 = x86_64

class MachoAnalysisTask(TurbiniaTask):
  """Task to analyse Mach-O Information"""

  REQUIRED_STATES = [
      state.ATTACHED, state.CONTAINER_MOUNTED, state.DECOMPRESSED
  ]

  _MAGIC_MULTI_SIGNATURE = b'\xca\xfe\xba\xbe'
  _MAGIC_32_SIGNATURE = b'\xce\xfa\xed\xfe'
  _MAGIC_64_SIGNATURE = b'\xcf\xfa\xed\xfe'

  # Code signature constants
  _CSMAGIC_EMBEDDED_SIGNATURE = b'\xfa\xde\x0c\xc0' # embedded form of signature data
  _CSMAGIC_CODEDIRECTORY = b'\xfa\xde\x0c\x02'      # CodeDirectory blob
  _CSMAGIC_BLOBWRAPPER = b'\xfa\xde\x0b\x01'        # CMS Signature, among other things

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
    """Retrieves Mach-O segment names.
    Args:
      binary (lief.MachO.Binary): binary to be parsed.
    Returns:
      symhash (str): symhash of the binary.
    """
    symbol_list = []
    for symbol in binary.imported_symbols:
      if symbol.type == 0 and symbol.origin == lief._lief.MachO.Symbol.ORIGIN.LC_SYMTAB:
        symbol_list.append(symbol.demangled_name)
    hasher = md5.MD5Hasher()
    hasher.Update(','.join(sorted(symbol_list)).encode())
    symhash = hasher.GetStringDigest()
    return symhash
  
  def _GetSections(self, segment, result):
    """Retrieves Mach-O segment section names.
    Args:
      segment (lief.MachO.SegmentCommand): segment to be parsed for sections.
      result (TurbiniaTaskResult): The object to place task results into.
    Returns:
      List[Sections]: Sections of the segments.
    """
    sections = []
    #result.log(f'----------- sections --------------')
    for sec in segment.sections:
      flags = []
      section = Section(flags)
      section.name = sec.name
      sections.append(section)
    #result.log(f'-----------------------------------')
    return sections

  def _GetSegments(self, binary, result):
    """Retrieves Mach-O segments.
    Args:
      binary (lief.MachO.Binary): binary to be parsed.
      result (TurbiniaTaskResult): The object to place task results into.
    Returns:
      List[Segments]: List of the segments.
    """
    segments = []
    #result.log(f'----------- segments --------------')
    for seg in binary.segments:
      sections = self._GetSections(seg, result)
      segment = Segment(sections)
      segment.name = seg.name
      segment.offset = hex(seg.file_offset)
      segment.size = seg.file_size
      segment.vaddr = hex(seg.virtual_address)
      segment.vsize = seg.virtual_size
      segments.append(segment)
    #result.log(f'-----------------------------------')
    return segments

  def _GetSymbols(self, binary, result):
    """Retrieves Mach-O symbols.
    Args:
      binary (lief.MachO.Binary): binary to be parsed.
      result (TurbiniaTaskResult): The object to place task results into.
    Returns:
      List[str]: List of the symbols.
    """
    symbols = []
    #result.log(f'----------- symbols --------------')
    for sym in binary.symbols:
      symbols.append(sym.demangled_name)
    #result.log(f'-----------------------------------')
    return symbols

  def _ParseCodeSignature(self, code_signature, result):
    """Parses Mach-O code signature.
       Details about the code signature structure on GitHub
       https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L267
    Args:
      code_signature (lief.MachO.CodeSignature): code signature to be parsed.
      result (TurbiniaTaskResult): The object to place task results into.
    Returns:
    """
    signature_bytes = code_signature.content.tobytes()
    #result.log(f'{code_signature.content.hex()}')
    #result.log(f'data_offset: {code_signature.data_offset}')
    #result.log(f'signature_bytes size: {len(signature_bytes)}')
    super_blob_magic = signature_bytes[0:4]
    if super_blob_magic != self._CSMAGIC_EMBEDDED_SIGNATURE:
      result.log(f'*** no embedded code signature detected ***')
    else:
      #result.log(f'*** found embedded signature ***')
      super_blob_length = int.from_bytes(signature_bytes[5:8], "big")
      generic_blob_count = int.from_bytes(signature_bytes[9:12], "big")
      #result.log(f'super_blob_length: ' + str(super_blob_length))
      #result.log(f'generic_blob_count: ' + str(generic_blob_count))
      for i in range(generic_blob_count):
        # lets walk through the CS_BlobIndex index[] entries
        # https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L280C15-L280C22
        ind = 'index_' + str(i)
        #result.log(f' {ind}')
        start_type = 13 + i*8 # uint32_t type
        start_offset = start_type + 4 # uint32_t offset
        #result.log(f' start_type:  {start_type}')
        #result.log(f' start_offset: {start_offset}')
        blob_index_type = signature_bytes[start_type:start_type+4]
        blob_index_offset = int.from_bytes(signature_bytes[start_offset:start_offset+3], "big")
        #result.log(f'   type  : {blob_index_type}')
        #result.log(f'   offset: {blob_index_offset}')
        generic_blob_magic = signature_bytes[blob_index_offset:blob_index_offset+4]
        generic_blob_length = int.from_bytes(signature_bytes[blob_index_offset+4:blob_index_offset+8], "big")
        #result.log(f'     magic : {generic_blob_magic}')
        #result.log(f'     length: {generic_blob_length}')
        if generic_blob_magic == self._CSMAGIC_CODEDIRECTORY:
          # TODO: extract team_id_offset pointing to team_id string
          result.log(f'     found CSMAGIC_CODEDIRECTORY, TODO: extract team_id string')
        elif generic_blob_magic == self._CSMAGIC_BLOBWRAPPER:
          result.log(f'     found CSMAGIC_BLOBWRAPPER, TODO: decide on signer info to extract')
          blobwrapper_base = blob_index_offset+8
          cert = signature_bytes[blobwrapper_base:blobwrapper_base+generic_blob_length]
          #result.log(f'{cert}')
          content_info = cms.ContentInfo.load(cert)
          #result.log(f'{content_info}')
          signed_data = content_info['content']
          signed_data_version = signed_data['version']
          encap_content_info = signed_data['encap_content_info']
          signer = signed_data['signer_infos'][0]
          signer_version = signer['version']
          #result.log(f'----------- signer info -----------')
          #result.log(f'{signer.native}')
          #result.log(f'-------- signer identifier --------')
          signer = signer['sid'].native
          #result.log(f'{signer}')
          #result.log(f'-----------------------------------')
          #result.log(f'-------- signed attributes --------')
          #attrs = signer['signed_attrs'].native
          #result.log(f'{attrs}')

  def _CpuType(self, cpu_type):
    """Translates CPU type identifier to string.
    Args:
      cpu_type (int): CPU type identifier.
    Returns:
      (str): CPU type string.
    """
    if cpu_type == lief.MachO.Header.CPU_TYPE.ANY:
      return "ANY"
    elif cpu_type == lief.MachO.Header.CPU_TYPE.ARM:
      return "ARM"
    elif cpu_type == lief.MachO.Header.CPU_TYPE.ARM64:
      return "ARM64"
    elif cpu_type == lief.MachO.Header.CPU_TYPE.MC98000:
      return "MC98000"
    elif cpu_type == lief.MachO.Header.CPU_TYPE.MIPS:
      return "MIPS"
    elif cpu_type == lief.MachO.Header.CPU_TYPE.POWERPC:
      return "POWERPC"
    elif cpu_type == lief.MachO.Header.CPU_TYPE.POWERPC64:
        return "POWERPC64"
    elif cpu_type == lief.MachO.Header.CPU_TYPE.SPARC:
        return "SPARC"
    elif cpu_type == lief.MachO.Header.CPU_TYPE.X86:
        return "X86"
    elif cpu_type == lief.MachO.Header.CPU_TYPE.X86_64:
      return "X86_64"
    else:
      return ""
    
  def _ParseMachoFatBinary(self, macho_fd, evidence, result, macho_path, file_name):
    """Parses a Mach-O fat binary.
    Args:
      macho_fd (int): file descriptor to the fat binary.
      evidence (Evidence object):  The evidence to process
      result (TurbiniaTaskResult): The object to place task results into.
      macho_path (str): path to the fat binary.
      file_name (str): file name of the fat binary.
    Returns:
      FatBinary: the parsed Mach-O Fat Binary details.
    """
    result.log(f'---------- start fat binary ------------')
    macho_fd.seek(0)
    data = macho_fd.read()
    hashes = Hashes()
    hashes.md5 = self._GetDigest(md5.MD5Hasher(), data)
    hashes.sha256 = self._GetDigest(sha256.SHA256Hasher(), data)
    parsed_fat_binary = ParsedFatBinary(hashes)
    parsed_fat_binary.entropy = self._GetDigest(entropy.EntropyHasher(), data)
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
    result.log(f'------------ start binary --------------')
    fat_offset = binary.fat_offset
    binary_size = binary.original_size
    macho_fd.seek(fat_offset)
    data = macho_fd.read(binary_size)
    hashes = Hashes()
    hashes.md5 = self._GetDigest(md5.MD5Hasher(), data)
    hashes.sha256 = self._GetDigest(sha256.SHA256Hasher(), data)
    hashes.symhash = self._GetSymhash(binary)
    parsed_binary = ParsedBinary(hashes=hashes, segments=None, symbols=None)
    parsed_binary.entropy = self._GetDigest(entropy.EntropyHasher(), data)
    parsed_binary.size = binary_size
    parsed_binary.fat_offset = fat_offset
    parsed_binary.segments = self._GetSegments(binary, result)
    parsed_binary.symbols = self._GetSymbols(binary, result)
    #if binary.has_code_signature:
    #  # TODO: Do something useful with the signarure
    #  #result.log(f'signature size: {binary.code_signature.data_size}')
    #  self._ParseCodeSignature(binary.code_signature, result)
    return parsed_binary

  def _WriteParsedMachoResults(self, file_name, parsed_macho):
    """Outputs the parsed Mach-O results.
    Args:
        parsed_macho(ParsedMacho): the parsed Mach-O details
    Returns:
        TurbiniaTaskResult object.
    """
    # Write the Mach-O Info to the output file.
    output_file_name = f'{file_name}.json'
    output_file_path=os.path.join(self.output_dir, output_file_name)
    with open(output_file_path, 'w') as fh:
      fh.write(f'{json.dumps(parsed_macho.__dict__, default=lambda o: o.__dict__, indent=2)}\n')
      fh.close()

  def run(self, evidence, result):
    """Run the Mach-O worker.
    Args:
        evidence (Evidence object):  The evidence to process
        result (TurbiniaTaskResult): The object to place task results into.
    Returns:
        TurbiniaTaskResult object.
    """
    # Where to store the resulting output file.
    output_file_name = 'macho_analysis.txt'
    output_file_path = os.path.join(self.output_dir, output_file_name)

    # We output a report.
    output_evidence = ReportText(source_path=output_file_path)
    parsed_binaries = 0
    parsed_fat_binaries = 0

    # traverse root directory, and list directories as dirs and files as files
    for root, dirs, files in os.walk(evidence.local_path):
      for file in files:
        macho_path = os.path.join(root, file)
        try:
          macho_binary = lief.MachO.parse(macho_path, config=lief.MachO.ParserConfig.quick)
          macho_fd = open(macho_path, 'rb')
        except IOError as e:
           # 'Error opening Mach-O file: {0:s}'.format(str(e)))
          break

        if isinstance(macho_binary, lief.MachO.FatBinary):
          parsed_macho = ParsedMacho(signature=None, architecture=None, iocs=None, imports=None, exports=None, fat_binary=None, arm64=None, x86_64=None)
          parsed_macho.evidence = evidence.id
          parsed_macho.request = evidence.request_id
          parsed_macho.source_path = file
          parsed_macho.source_type = "file"
          parsed_macho.fat_binary = self._ParseMachoFatBinary(macho_fd, evidence, result, macho_path, file)
          parsed_fat_binaries += 1
          for binary in macho_binary:
            parsed_binary = self._ParseMachoBinary(macho_fd, evidence, binary, result, file)
            parsed_binaries += 1
            if binary.header.cpu_type == lief.MachO.Header.CPU_TYPE.ARM64:
              parsed_macho.arm64 = parsed_binary
            elif binary.header.cpu_type == lief.MachO.Header.CPU_TYPE.X86_64:
              parsed_macho.x86_64 = parsed_binary
          self._WriteParsedMachoResults(file, parsed_macho)
          result.log(f'{json.dumps(parsed_macho.__dict__, default=lambda o: o.__dict__)}')
        elif isinstance(macho_binary, lief.MachO.Binary):
          #parsed_macho = self._ParseMachoBinary(macho_fd, evidence, macho_binary, result, file)
          parsed_binaries += 1
          #self._WriteParsedMachoResults(parsed_macho)
          #result.log(f'{json.dumps(parsed_macho.__dict__, default=lambda o: o.__dict__)}')
        macho_fd.close()
        result.log(f'------------------------')

    summary = f'Parsed {parsed_fat_binaries} lief.MachO.FatBinary and {parsed_binaries} lief.MachO.Binary'
    output_evidence.text_data = os.linesep.join(summary) 
    result.report_data = os.linesep.join(summary)
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