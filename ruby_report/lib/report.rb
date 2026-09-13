require "json"

module SentinelMesh
  module Report
    module_function

    def summarize(snapshot)
      summary = snapshot.fetch("summary")
      [
        "SentinelMesh report",
        "Visible devices: #{summary.fetch('total')}",
        "New devices: #{summary.fetch('new')}",
        "Elevated risk: #{summary.fetch('elevated_risk')}"
      ].join("\n")
    end

    def from_stdin
      input = STDIN.read
      puts summarize(JSON.parse(input))
    end

    def export(snapshot, path)
      File.write(path, JSON.pretty_generate(snapshot) + "\n")
    end
  end
end

SentinelMesh::Report.from_stdin if $PROGRAM_NAME == __FILE__
