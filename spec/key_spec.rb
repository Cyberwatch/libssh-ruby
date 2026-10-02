require "spec_helper"

RSpec.describe LibSSH::Key do
  it "cannot be manually allocated" do
    expect { described_class.allocate }.to raise_error TypeError
  end
end
