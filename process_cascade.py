""" stream cascade processor """

class ProcessCascade():
    """ strace line parser generator """
    def __init__(self, processor, in_stream):
        if not ( hasattr(in_stream, '__next__') and callable(in_stream.__next__) ) :
            raise ValueError('invalid input')
        self.input = in_stream
        self.processor = processor()

    def __iter__(self):
        return self

    def __next__(self):
        """ read next line from stream, until it's parsable """
        if self.processor.has_split_cache() :
            return self.processor.get_split_cache()
        new_chunk = self.input.__next__()
        while new_chunk :
            parsed = self.processor.process(new_chunk)
            if parsed :
                return parsed
            new_chunk = self.input.__next__()
        raise StopIteration()
