"""Task for analysing ELF Information."""

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


class Hashes(object):

  def __init__(self):
    self.sha256 = ""
    self.md5 = ""
    self.ssdeep = ""
    self.tlsh = ""


class Section(object):

  def __init__(self):
    self.name = ""
    self.type = ""
    self.virtual_address = 0
    self.file_offset = 0
    self.flags = []
    self.size = 0
    self.entropy = 0


class Segment(object):

  def __init__(self, sections: List[Section]):
    self.type = ""
    self.flags = ""
    self.file_offset = 0
    self.virtual_size = 0
    self.physical_size = 0
    self.sections = sections


class Symbol(object):

  def __init__(self):
    self.name = ""
    self.type = ""
    self.version = ""
    self.value = ""
    self.visibility = ""
    self.binding = ""


class Library(object):

  def __init__(self):
    self.name = ""


class ParsedHeader(object):

  def __init__(self):
    self.entrypoint = 0
    self.file_type = ""
    self.header_size = 0
    self.identity_abi_version = 0
    self.identity_class = ""
    self.identity_data = ""
    self.identity_os_abi = ""
    self.identity_version = ""
    self.numberof_sections = 0
    self.numberof_segments = 0
    self.machine_type = ""
    self.object_file_version = ""
    self.processor_flags = ""
    self.program_header_offset = 0
    self.program_header_size = 0
    self.section_header_offset = 0
    self.section_header_size = 0


class ParsedElf(object):

  def __init__(
      self, hashes: Hashes, header: ParsedHeader, segments: List[Segment],
      imp_symbols: List[Symbol], exp_symbols: List[Symbol],
      dyn_symbols: List[Symbol], tab_symbols: List[Symbol],
      libaries: List[Library]):
    self.request = ""
    self.evidence = ""
    self.file_name = ""
    self.processing_time = 0
    self.virtual_size = 0
    self.hashes = hashes
    self.header = header
    self.segments = segments
    self.imported_symbols = imp_symbols
    self.exported_symbols = exp_symbols
    self.dynamic_symbols = dyn_symbols
    self.symtab_symbols = tab_symbols
    self.libaries = libaries


class ElfAnalysisTask(TurbiniaTask):
  """Task to analyse ELF Information"""

  REQUIRED_STATES = [state.ATTACHED, state.DECOMPRESSED]

  def __init__(self, *args, **kwargs):
    super(ElfAnalysisTask, self).__init__(*args, **kwargs)
    if TurbiniaTask.check_worker_role():
      try:
        import lief
        import tlsh
        import pyssdeep
        from plaso.analyzers.hashers import entropy
        from plaso.analyzers.hashers import md5
        from plaso.analyzers.hashers import sha256

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

  def _GetHashes(self, elf_fd, binary):
    """Parses a ELF binary.
    Args:
      elf_fd (int): file descriptor to the binary.
      binary (lief.ELF.Binary): binary to compute the hashes on.
    Returns:
      Hashes: the computed hashes.
    """
    binary_size = binary.virtual_size
    elf_fd.seek(0)
    data = elf_fd.read(binary_size)
    hashes = Hashes()
    hashes.md5 = self._GetDigest(self._md5.MD5Hasher(), data)
    hashes.sha256 = self._GetDigest(self._sha256.SHA256Hasher(), data)
    hashes.tlsh = self._tlsh.hash(data)
    hashes.ssdeep = self._pyssdeep.get_hash_buffer(data)
    return hashes

  def _GetSections(self, segment):
    """Retrieves the sections of a ELF binary segment.
    Args:
      segment (lief.ELF.Binary.Segment): segment to extract the sections from.
    Returns:
      Sections: the extracted sections.
    """
    sects = segment.sections
    sections = []
    if len(sects) > 0:
      for sect in sects:
        section = Section()
        section.name = sect.name
        section.type = str(sect.type).split(".")[-1]
        section.virtual_address = sect.virtual_address
        section.file_offset = sect.file_offset
        section.size = sect.size
        section.entropy = abs(sect.entropy)
        for flag in sect.flags_list:
          section.flags.append(str(flag).split(".")[-1])
        sections.append(section)
    return sections

  def _GetSegments(self, binary):
    """Retrieves the segments of a ELF binary.
    Args:
      binary (lief.ELF.Binary): binary to extract the segments from.
    Returns:
      Segments: the extracted segments.
    """
    segments = []
    sgmts = binary.segments
    if len(sgmts) > 0:
      for sgmt in sgmts:
        segment = Segment(self._GetSections(sgmt))
        flags_str = ["-"] * 3
        if self._lief.ELF.Segment.FLAGS.R in sgmt:
          flags_str[0] = "r"
        if self._lief.ELF.Segment.FLAGS.W in sgmt:
          flags_str[1] = "w"
        if self._lief.ELF.Segment.FLAGS.X in sgmt:
          flags_str[2] = "x"
        segment.flags = "".join(flags_str)
        segment.type = str(sgmt.type).split(".")[-1]
        segment.file_offset = sgmt.file_offset
        segment.virtual_address = sgmt.virtual_address
        segment.virtual_size = sgmt.virtual_size
        segment.physical_size = sgmt.physical_size
        segments.append(segment)
    return segments

  def _GetSymbols(self, symbols):
    """Retrieves the symbols of a ELF binary.
    Args:
      symbols (lief.ELF.Binary.it_filter_symbols): symbols.
    Returns:
      Symbols: the extracted symbols.
    """
    symbls = []
    if len(symbols) > 0:
      for symbl in symbols:
        symbol = Symbol()
        symbol.name = symbl.name
        symbol.type = str(symbl.type).split(".")[-1]
        symbol.version = str(symbl.symbol_version) if symbl.has_version else ""
        symbol.value = symbl.value
        symbol.visibility = str(symbl.visibility).split(".")[-1]
        symbol.binding = str(symbl.binding).split(".")[-1]
        symbls.append(symbol)
    return symbls

  def _GetLibraries(self, binary):
    """Retrieves the shared libraries of a ELF binary.
    Args:
      binary (lief.ELF.Binary): binary to extract the libraries from.
    Returns:
      Libraries: the extracted segments.
    """
    libaries = []
    # Get the list of shared libraries
    shared_libs = binary.libraries
    for shared_lib in shared_libs:
      library = Library()
      library.name = shared_lib
      libaries.append(library)
    return libaries

  def _ParseHeader(self, header):
    """Parses a ELF binary.
    Args:
      header (lief.ELF.Binary.Header): header to be parsed.
    Returns:
      ParsedHeader: the parsed header details.
    """
    parsed_header = ParsedHeader()
    eflags_str = ""
    if header.machine_type == self._lief.ELF.ARCH.ARM:
      eflags_str = " - ".join(
          [str(s).split(".")[-1] for s in header.arm_flags_list])

    if header.machine_type in [self._lief.ELF.ARCH.MIPS,
                               self._lief.ELF.ARCH.MIPS_RS3_LE,
                               self._lief.ELF.ARCH.MIPS_X]:
      eflags_str = " - ".join(
          [str(s).split(".")[-1] for s in header.mips_flags_list])

    if header.machine_type == self._lief.ELF.ARCH.PPC64:
      eflags_str = " - ".join(
          [str(s).split(".")[-1] for s in header.ppc64_flags_list])

    if header.machine_type == self._lief.ELF.ARCH.HEXAGON:
      eflags_str = " - ".join(
          [str(s).split(".")[-1] for s in header.hexagon_flags_list])

    if header.machine_type == self._lief.ELF.ARCH.LOONGARCH:
      eflags_str = " - ".join(
          [str(s).split(".")[-1] for s in header.loongarch_flags_list])

    parsed_header.entrypoint = header.entrypoint
    parsed_header.file_type = str(header.file_type).split(".")[-1]
    parsed_header.header_size = header.header_size
    parsed_header.identity_abi_version = header.identity_abi_version
    parsed_header.identity_class = str(header.identity_class).split(".")[-1]
    parsed_header.identity_data = str(header.identity_data).split(".")[-1]
    parsed_header.identity_os_abi = str(header.identity_os_abi).split(".")[-1]
    parsed_header.identity_version = str(header.identity_version).split(".")[-1]
    parsed_header.numberof_sections = header.numberof_sections
    parsed_header.numberof_segments = header.numberof_segments
    parsed_header.machine_type = str(header.machine_type).split(".")[-1]
    parsed_header.object_file_version = str(
        header.object_file_version).split(".")[-1]
    parsed_header.processor_flags = str(header.processor_flag) + eflags_str
    parsed_header.program_header_offset = header.program_header_offset
    parsed_header.program_header_size = header.program_header_size
    parsed_header.section_header_offset = header.section_header_offset
    parsed_header.section_header_size = header.section_header_size
    return parsed_header

  def _WriteParsedElfResults(self, file_name, parsed_elf, base_dir):
    """Outputs the parsed ELF results.
    Args:
        file_name(str): the name of the parsed ELF file
        parsed_elf(ParsedElf): the parsed ELF details
        base_dir(str): the base directory for the parsed ELF file
    Returns:
        TurbiniaTaskResult object.
    """
    # Write the ELF to the output file.
    output_file_name = f'{file_name}.json'
    output_dir_path = os.path.join(self.output_dir, 'reports', base_dir)
    if not os.path.exists(output_dir_path):
      os.makedirs(output_dir_path)
    output_file_path = os.path.join(output_dir_path, output_file_name)
    with open(output_file_path, 'w') as fh:
      # Plain vanilla json.dumps() doesn't support custom classes.
      # https://stackoverflow.com/questions/3768895/how-to-make-a-class-json-serializable
      fh.write(
          f'{json.dumps(parsed_elf.__dict__, default=lambda o: o.__dict__, indent=2)}\n'
      )
      fh.close()

  def _CurrentTimeMillis(self):
    return round(time.time() * 1000)

  def run(self, evidence, result):
    """Run the ELF worker.
    Args:
        evidence (Evidence object):  The evidence to process
        result (TurbiniaTaskResult): The object to place task results into.
    Returns:
        TurbiniaTaskResult object.
    """
    # Where to store the resulting output file.
    start_time = self._CurrentTimeMillis()
    output_file_name = 'elf_analysis.txt'
    output_file_path = os.path.join(self.output_dir, output_file_name)

    # We output a report.
    output_evidence = ReportText(source_path=output_file_path)
    parsed_binaries = 0

    # traverse root directory, and list directories as dirs and files as files
    for root, dirs, files in os.walk(evidence.local_path):
      for file in files:
        base_dir = os.path.relpath(root, evidence.local_path)
        elf_path = os.path.join(root, file)
        try:
          elf_binary = self._lief.ELF.parse(elf_path)
          elf_fd = open(elf_path, 'rb')
        except IOError as e:
          result.log(f'Error opening ELF file: {str(e)}')
          break

        if isinstance(elf_binary, self._lief.ELF.Binary):
          parsed_binaries += 1
          hashes = self._GetHashes(elf_fd, elf_binary)
          header = self._ParseHeader(elf_binary.header)
          segments = self._GetSegments(elf_binary)
          imp_symbols = self._GetSymbols(elf_binary.imported_symbols)
          exp_symbols = self._GetSymbols(elf_binary.exported_symbols)
          dyn_symbols = self._GetSymbols(elf_binary.dynamic_symbols)
          tab_symbols = self._GetSymbols(elf_binary.symtab_symbols)
          libaries = self._GetLibraries(elf_binary)
          parsed_elf = ParsedElf(
              hashes, header, segments, imp_symbols, exp_symbols, dyn_symbols,
              tab_symbols, libaries)
          parsed_elf.evidence = evidence.id
          parsed_elf.file_name = file
          parsed_elf.virtual_size = elf_binary.virtual_size
          parsed_elf.request = evidence.request_id
          parsed_elf.processing_time = self._CurrentTimeMillis() - start_time
          self._WriteParsedElfResults(file, parsed_elf, base_dir)
        else:
          result.log(f'Skipping unsupported format: {file}')
        elf_fd.close()

    summary = f'Parsed {parsed_binaries} lief.ELF.Binary'
    output_evidence.text_data = summary
    result.report_data = summary
    result.report_priority = Priority.LOW

    # Write the ELF Info to the output file.
    with open(output_file_path, 'wb') as fh:
      fh.write(output_evidence.text_data.encode('utf8'))
      fh.write('\n'.encode('utf8'))
      fh.close()

    # Add the output evidence to the result object.
    result.add_evidence(output_evidence, evidence.config)
    result.close(self, success=True, status=summary)

    return result