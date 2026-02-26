function transform(response)
  -- Example: attach provenance header and normalize missing content-type.
  response.headers["x-replayproxy-example"] = "on-response"
  if response.headers["content-type"] == nil then
    response.headers["content-type"] = "application/json"
  end
  return response
end
