import { prefixWith0x } from "../src/util/Util";

describe("basic test", () => {
  it("should return", () => {
    expect.assertions(1);
    const result = prefixWith0x("1234");
    expect(result).toBe("0x1234");
  });
});
