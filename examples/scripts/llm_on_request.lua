function transform(request)
  -- Example: normalize auth + add trace marker before matching/forwarding.
  if request.headers["authorization"] == nil then
    request.headers["authorization"] = "Bearer ${OPENAI_API_KEY}"
  end
  request.headers["x-replayproxy-example"] = "on-request"
  return request
end
