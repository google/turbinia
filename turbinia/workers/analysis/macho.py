"""Task for analysing Mach-O Information."""

import lief
import os

from turbinia import TurbiniaException

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

    evidence_file_name = 'ls.mac'
    # We will extract the OS information from os-release
    macho_path = os.path.join(evidence.local_path, evidence_file_name)
    macho_info = ''
    result.log(f'macho_path: {macho_path}')
    try:
      macho_binary = lief.MachO.parse(macho_path, config=lief.MachO.ParserConfig.quick)
      macho_fd = open(macho_path, 'rb')
    except IOError as e:
      result.close(
           self, success=False,
           status='Error opening Mach-O file: {0:s}'.format(str(e)))
      return result

    if isinstance(macho_binary, lief.MachO.FatBinary):
      macho_info = 'Mach-O is lief.MachO.FatBinary'
      self._ParseMachoFatBinary(macho_fd, result, macho_path, evidence_file_name)
      for binary in macho_binary:
        self._ParseMachoBinary(macho_fd, binary, result, evidence_file_name)
    elif isinstance(macho_binary, lief.MachO.Binary):
      macho_info = 'Mach-O is lief.MachO.Binary'
      self._ParseMachoBinary(macho_fd, macho_binary, result, evidence_file_name)

    macho_fd.close()

    output_evidence.text_data = os.linesep.join(macho_info) 
    result.report_data = os.linesep.join(macho_info)
    result.report_priority = Priority.LOW
    summary = macho_info

    # Write the Mach-O Info to the output file.
    with open(output_file_path, 'wb') as fh:
      fh.write(output_evidence.text_data.encode('utf8'))
      fh.write('\n'.encode('utf8'))

    # Add the output evidence to the result object.
    result.add_evidence(output_evidence, evidence.config)
    result.close(self, success=True, status=summary)

    return result