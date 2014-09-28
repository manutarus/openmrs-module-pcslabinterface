package org.openmrs.module.pcslabinterface.rules;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * PCS is sending some Confirmation results with null values
 * 
 * @author akwatuha
 */
public class RemoveAfbConfirmationNullValueSegments extends RegexTransformRule {

	// this regex ensures that the segment is for DNA PCR with a null value
	private Pattern valuePattern = Pattern
			.compile("OBX\\|\\d*\\|CWE\\|2311\\^CONFIRMATION\\^99DCT\\|\\|\\^\\^99DCT\\|.+");


	/**
	 * initializes the regex pattern for matching
	 *
	 * @should only match DNA PCR tests with null values
	 */
	public RemoveAfbConfirmationNullValueSegments() {
		// this regex ensures that the segment is for DNA PCR with a null value
		super("OBX\\|\\d*\\|CWE\\|2311\\^CONFIRMATION\\^99DCT\\|\\|\\^\\^99DCT\\|.+");
	}

	/**
	 * completely replaces the OBX with an NTE segment indicating it was removed
	 * 
	 * @should return a null string if matched
	 */
	@Override
	public String transform(String test) {
		// check for numeric concept
		Matcher m = valuePattern.matcher(test);
		if (!m.matches())
			return test;

		// return nothing ... so that the test can be removed
		return null;
	}

}
