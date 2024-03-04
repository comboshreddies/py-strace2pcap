#!/usr/bin/env python3
""" stream cascade processor """

class ProcessCascade(object):
    """ strace line parser generator """
    def __init__(self, parser, in_stream):
        if not ( hasattr(in_stream, '__next__') and callable(in_stream.__next__) ) :
            raise ValueError('invalid input')
        self.input = in_stream
        self.processor = parser()

    def __iter__(self):
        return self

    def __next__(self):
        """ read next line from stream, until it's parsable """
        new_chunk = self.input.__next__()
        while new_chunk :
            parsed = self.processor.process(new_chunk)
            if parsed :
                return parsed
            new_chunk = self.input.__next__()
        raise StopIteration()
