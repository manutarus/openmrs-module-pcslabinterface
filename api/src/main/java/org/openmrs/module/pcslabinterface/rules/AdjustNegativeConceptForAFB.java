package org.openmrs.module.pcslabinterface.rules;

import org.openmrs.module.pcslabinterface.PcsLabInterfaceConstants;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Several numeric values for HIV Viral Load are simply digits with commas in
 * the thousands and millions places. These should be converted to valid HL7
 * numeric values by stripping the commas and adding a comment.
 * 
 * @author akwatuha
 */
public class AdjustNegativeConceptForAFB extends RegexTransformRule {

	// this regex ensures that the value has only digits and/or commas in it
	private Pattern valuePattern = Pattern
			.compile("OBX\\|\\d*\\|CWE\\|307\\^AFB Microscopy sputum\\^99DCT\\|[^\\|]*\\|(\\^NEGATIVE\\^99DCT)\\|.*");

	/**
	 * initializes the regex pattern for matching on a specific concept
	 *
	 * @should match only numeric OBX segments for AFB Microscopy with commas in the value
	 * @should match values with other characters as long as there is at least one comma
	 */
	public AdjustNegativeConceptForAFB() {
		// the follow regex ensures that the concept is AFB Microscopy and the
		// value has at least one comma in it
		super(
				"OBX\\|\\d*\\|CWE\\|307\\^AFB Microscopy sputum\\^99DCT\\|[^\\|]*\\|\\^NEGATIVE\\^99DCT.*");
	}

	/**
	 * transforms the test string by stripping commas from the value and
	 * appending a comment (NTE segment) with the original value
	 * 
	 * @should replace improper concept reference
	 * @should not replace proper concept reference
	 */
	@Override
	public String transform(String test) {
		// check to make sure the value is truly just numbers and commas
		Matcher m = valuePattern.matcher(test);
		if (!m.matches())
			return test;

		// replace first occurrence of value with newValue
		test = test.replaceFirst("\\^Negative\\^99DCT", "664^NEGATIVE^99DCT");

		// append a comment describing the change
		return test.concat(PcsLabInterfaceConstants.MESSAGE_EOL_SEQUENCE)
				.concat("NTE|||")
				.concat(PcsLabInterfaceConstants.LAB_VALUE_MODIFIED)
				.concat("^Negative^99DCT");
	}
}
