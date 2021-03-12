import os
import sys
import argparse
from pprint import pprint

# PE file related imports
import pefile
# import lief

# Relevant modules
from features.asm import ASMExtractor
from features.section_info import SectionInfoExtractor

# Dictionary of available feature extractors, along with keyword arguments
feature_extractors = {
  ASMExtractor: None,
  SectionInfoExtractor: None,
}

if __name__ == '__main__':
  parser = argparse.ArgumentParser(description="Execute feature extraction for an input PE file")
  parser.add_argument('file', type=str, help="Input PE file to extract features for")
  args = parser.parse_args()

  features = {}

  for extractor in feature_extractors:
    kwargs = feature_extractors[extractor]
    e = extractor(args.file)
    features.update(e.extract(kwargs=kwargs))

  pprint(features)