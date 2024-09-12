"""Task for analysing Mach-O Information."""

import lief
import os

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

  def _GetSectionNames(self, segment, result):
    """Retrieves Mach-O segment section names.
    Args:
      segment (lief.MachO.SegmentCommand): binary to be parsed.
      result (TurbiniaTaskResult): The object to place task results into.

    Returns:
      list[str]: names of the segments.
    """
    section_names = []
    result.log(f'----------- sections --------------')
    for section in segment.sections:
      result.log(f'  {section.name}')
      section_names.append(section.name)
    result.log(f'-----------------------------------')
    return section_names

  def _GetSegmentNames(self, binary, result):
    """Retrieves Mach-O segment names.
    Args:
      binary (lief.MachO.Binary): binary to be parsed.
      result (TurbiniaTaskResult): The object to place task results into.

    Returns:
      list[str]: names of the segments.
    """
    segment_names = []
    result.log(f'----------- segments --------------')
    for segment in binary.segments:
      section_names = []
      result.log(f'{segment.name}')
      segment_names.append(segment.name)
      section_names = self._GetSectionNames(binary, result)
      # TODO: How do we want to surface the section names
    result.log(f'-----------------------------------')
    return segment_names

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
    result.log(f'data_offset: {code_signature.data_offset}')
    result.log(f'signature_bytes size: {len(signature_bytes)}')
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
          result.log(f'----------- signer info -----------')
          result.log(f'{signer.native}')
          result.log(f'-------- signer identifier --------')
          signer = signer['sid'].native
          result.log(f'{signer}')
          result.log(f'-----------------------------------')
          #result.log(f'-------- signed attributes --------')
          #attrs = signer['signed_attrs'].native
          #result.log(f'{attrs}')

  def _ParseMachoFatBinary(self, macho_fd, result, macho_path, file_name):
    """Parses a Mach-O fat binary.
    Args:
      macho_fd (int): file descriptor to the fat binary.
      result (TurbiniaTaskResult): The object to place task results into.
      macho_path (str): path to the fat binary.
      file_name (str): file name of the fat binary.
    """
    result.log(f'---------- start fat binary ------------')
    fat_binary_stats = os.stat(macho_path)
    fat_binary_size = fat_binary_stats.st_size
    result.log(f'fat binary size in Bytes is {fat_binary_size}')
    macho_fd.seek(0)
    data = macho_fd.read()
    ent = self._GetDigest(entropy.EntropyHasher(), data)
    md5_hash = self._GetDigest(md5.MD5Hasher(), data)
    sha256_hash = self._GetDigest(sha256.SHA256Hasher(), data)
    result.log(f'entropy: {ent}')
    result.log(f'md5: {md5_hash}')
    result.log(f'sha256: {sha256_hash}')
    result.log(f'----------- end fat binary -------------')

  def _ParseMachoBinary(self, macho_fd, binary, result, file_name):
    """Parses a Mach-O binary.
    Args:
      macho_fd (int): file descriptor to the fat binary.
      binary (lief.MachO.Binary): binary to be parsed.
      result (TurbiniaTaskResult): The object to place task results into.
      filename (str): file name of the binary.
    """
    result.log(f'------------ start binary --------------')
    result.log(f'{binary.header.cpu_type}')
    fat_offset = binary.fat_offset
    original_size = binary.original_size
    result.log(f'fat offset: {fat_offset}')
    result.log(f'size: {original_size}')
    macho_fd.seek(fat_offset)
    data = macho_fd.read(original_size)
    ent = self._GetDigest(entropy.EntropyHasher(), data)
    md5_hash = self._GetDigest(md5.MD5Hasher(), data)
    sha256_hash = self._GetDigest(sha256.SHA256Hasher(), data)
    sym_hash = self._GetSymhash(binary)
    result.log(f'entropy: {ent}')
    result.log(f'md5: {md5_hash}')
    result.log(f'sha256: {sha256_hash}')
    result.log(f'symhash: {sym_hash}')
    if binary.has_code_signature:
      # TODO: Do something useful with the signarure
      result.log(f'signature size: {binary.code_signature.data_size}')
      self._ParseCodeSignature(binary.code_signature, result)
    segment_names = self._GetSegmentNames(binary, result)
    result.log(f'------------- end binary ---------------')

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

    # traverse root directory, and list directories as dirs and files as files
    macho_info = ''
    parsed_binaries = 0
    parsed_fat_binaries = 0
    
    for root, dirs, files in os.walk(evidence.local_path):
      for file in files:
        #result.log(f'root: {root}, file: {file}')
        macho_path = os.path.join(root, file)
        result.log(f'macho_path: {macho_path}')
        try:
          macho_binary = lief.MachO.parse(macho_path, config=lief.MachO.ParserConfig.quick)
          macho_fd = open(macho_path, 'rb')
        except IOError as e:
           # 'Error opening Mach-O file: {0:s}'.format(str(e)))
          break

        if isinstance(macho_binary, lief.MachO.FatBinary):
          macho_info = 'Mach-O is lief.MachO.FatBinary'
          self._ParseMachoFatBinary(macho_fd, result, macho_path, file)
          parsed_fat_binaries += 1
          for binary in macho_binary:
            self._ParseMachoBinary(macho_fd, binary, result, file)
            parsed_binaries += 1
        elif isinstance(macho_binary, lief.MachO.Binary):
          macho_info = 'Mach-O is lief.MachO.Binary'
          self._ParseMachoBinary(macho_fd, macho_binary, result, file)
          parsed_binaries += 1
        macho_fd.close()
        result.log(f'------------------------')

    output_evidence.text_data = os.linesep.join(macho_info) 
    result.report_data = os.linesep.join(macho_info)
    result.report_priority = Priority.LOW
    summary = f'Parsed {parsed_fat_binaries} lief.MachO.FatBinary and {parsed_binaries} lief.MachO.Binary'

    # Write the Mach-O Info to the output file.
    with open(output_file_path, 'wb') as fh:
      fh.write(output_evidence.text_data.encode('utf8'))
      fh.write('\n'.encode('utf8'))

    # Add the output evidence to the result object.
    result.add_evidence(output_evidence, evidence.config)
    result.close(self, success=True, status=summary)

    return result