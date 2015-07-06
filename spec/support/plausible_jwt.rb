def plausible_message_signature?(str)
  _parts_count(str) == 3
end

def plausible_unsecured_jws?(str)
  _parts_count(str) == 2
end

def _parts_count(str)
  str.split('.').length
end
