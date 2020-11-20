package com.hedera.services.bdd.suites.misc;
/*-
 * ‌
 * Hedera Services Test Clients
 * ​
 * Copyright (C) 2018 - 2020 Hedera Hashgraph, LLC
 * ​
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ‍
 */
import com.hedera.services.bdd.spec.HapiApiSpec;
import com.hedera.services.bdd.spec.HapiPropertySource;
import com.hedera.services.bdd.suites.HapiApiSuite;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Arrays;
import java.util.List;

import static com.hedera.services.bdd.spec.HapiApiSpec.defaultHapiSpec;
import static com.hedera.services.bdd.spec.utilops.UtilVerbs.sleepFor;
import static com.hedera.services.bdd.spec.utilops.UtilVerbs.withOpContext;

public class SleepOnly extends HapiApiSuite {
	private static final Logger log =
			LogManager.getLogger(com.hedera.services.bdd.suites.misc.SleepOnly.class);
	private int sleepMin = 1;

	public static void main(String... args) {
		new SleepOnly().runSuiteSync();
	}

	@Override
	protected Logger getResultsLogger() {
		return log;
	}

	@Override
	protected List<HapiApiSpec> getSpecsInSuite() {
		return Arrays.asList(
				SleepOnly()
		);
	}

	private HapiApiSpec SleepOnly() {
		return defaultHapiSpec("SleepOnly")
				.given(
						withOpContext((spec, opLog) -> {
							HapiPropertySource ciProps = spec.setup().ciPropertiesMap();
							if (ciProps.has("sleepMin")) {
								sleepMin = ciProps.getInteger("sleepMin");
								log.info("Client set sleepMin " + sleepMin);
							}
						})
				).when(
						sleepFor(sleepMin * 60 * 1000)
				).then(
				);
	}
}
