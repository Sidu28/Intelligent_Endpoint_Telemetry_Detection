import os
import sys
import argparse

# PE file related imports
import pefile
# import lief

# Relevant modules
from features.asm import ASMExtractor

# Dictionary of available feature extractors, along with keyword arguments
feature_extractors = {
  ASMExtractor: None
}

if __name__ == '__main__':
  parser = argparse.ArgumentParser(description="Execute feature extraction for an input PE file")
  parser.add_argument('file', type=str, help="Input PE file to extract features for")
  args = parser.parse_args()

  features = {}

  for extractor in feature_extractors:
    e = extractor(args.file)
    features.update(e.extract())

  print(features)