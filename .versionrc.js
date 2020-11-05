module.exports = {
  // Skip commit and tag, we will do these steps manually
  skip: {
    commit: true,
    tag: true,
  },
  header: `# Changelog\n\nAll notable changes to this project will be documented in this file.\n`,
  types: [
    { type: "feat", section: "🚀 Features" },
    { type: "fix", section: "🐛 Bug Fixes" },
    { type: "chore", hidden: true },
    { type: "docs", hidden: true },
    { type: "style", hidden: true },
    { type: "refactor", hidden: true },
    { type: "perf", hidden: true },
    { type: "test", hidden: true },
  ],
};