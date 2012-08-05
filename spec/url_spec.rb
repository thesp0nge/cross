require 'spec_helper'

describe "Url fuzzer" do
  let (:url) {Cross::Url.new("http://localhost:8080/WebGoat/attack?Screen=130&menu=900")}
  it "will recognize the param list" do
    url.params.class.should == Array
    url.params.size.should == 2
  end

  it "will recognize parameter names" do
    url.params[0][:name].should == 'Screen'
    url.params[1][:name].should == 'menu'
  end

  it "will recognize parameter values" do
    url.params[0][:value].should == "130"
    url.params[1][:value].should == "900"
  end

  it "will provide a get shortcut for getting parameters value" do
    url.get("Screen").should == "130"
    url.get("menu").should == "900"
  end

  it "will handle errors smoothly" do
    url.get("nonexistent").should be_nil
  end

  it "will make a copy of parameters" do
    url.original_params.should == url.params
  end

  it "will make params Array to be reverted as string" do
    url.params_to_url.should == "Screen=130&menu=900"
  end

  describe "will provide an handy set shortcut that" do
    it "sets an existing params to a given value" do
      url.set("Screen", "123")
      url.get("Screen").should == "123"
    end

    it "handle the error condition smootly" do
      url.set("nonexistent", false)
      url.original_params.should == url.params
    end

    it "won't change the original params" do
      url.set("Screen", "123")
      url.original_params.should_not == url.params
    end
  end
  it "will fuzz" do
    url.fuzz("Screen", "12").should == "http://localhost:8080/WebGoat/attack?Screen=12&menu=900"
    url.fuzz("Screen", "afuzztest").should == "http://localhost:8080/WebGoat/attack?Screen=afuzztest&menu=900"
    url.fuzz("menu", "11").should == "http://localhost:8080/WebGoat/attack?Screen=afuzztest&menu=11"
  end

  it "will fuzz honoring original params if requested" do
    url.reset
    url.get("Screen").should == "130"
    url.get("menu").should == "900"
    url.fuzz("Screen", "12").should == "http://localhost:8080/WebGoat/attack?Screen=12&menu=900"
    url.reset
    url.get("Screen").should == "130"
    url.get("menu").should == "900"
    url.fuzz("Screen", "afuzztest").should == "http://localhost:8080/WebGoat/attack?Screen=afuzztest&menu=900"
    url.reset
    url.get("Screen").should == "130"
    url.get("menu").should == "900"
    url.fuzz("menu", "11").should == "http://localhost:8080/WebGoat/attack?Screen=130&menu=11"

  end
end
